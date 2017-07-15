<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Admin extends CI_Controller {
	/* Многие пожелания добра:
	*  https://github.com/fr05t1k/esia/blob/master/src/OpenId.php
	*  https://habrahabr.ru/post/276313/
	*
	*  DO: correct a signature check
	*/

	function __construct() {
		parent::__construct();
		$this->load->model("logmodel");
		$this->load->model("verifymodel");
		$this->load->model("userdatamodel");
	}

	public $dataProfile = array(
		'openid'     => array("scopes" => array('openid'),								"requests" => array('openid')),
		'contacts'   => array("scopes" => array('contacts'),							"requests" => array('contacts')),
		'fullname'   => array("scopes" => array('fullname'),							"requests" => array('fullname')),
		'birthplace' => array("scopes" => array('birthplace'),							"requests" => array('birthplace')),
		'address'    => array("scopes" => array('birthplace', 'contacts'),				"requests" => array('birthplace', 'address')),
		'fulldata'   => array("scopes" => array('birthplace', 'contacts', 'fullname'),	"requests" => array('birthplace', 'address', 'contacts', 'fullname'))
	);

	public $rTokens = array(
		'openid'     => 'openid',
		'contacts'   => 'contacts',
		'address'    => 'contacts',
		'fullname'   => 'fullname',
		'birthplace' => 'birthplace',
	);

	public $oid                   = null;
	public $tlog                  = null;
	public $portalUrl             = 'https://esia.gosuslugi.ru/';
	public $logMode               = 'logfile'; //both, none, logfile, screen
	private $state                = null;

	/* Cryptografic & hash function wrappers */

	/**
	* Generate state as UUID-formed string
	* 
	* @return string
	*/
	private function getState() {
		return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff),
			mt_rand(0, 0x0fff) | 0x4000,
			mt_rand(0, 0x3fff) | 0x8000,
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff),
			mt_rand(0, 0xffff)
		);
	}

	/**
	* Signing a message which
	* will be send in client_secret param
	* 
	* @param string $src
	* @return string
	*/
	private function getSecret($src) {
		$sign				= null;
		$privateKeyPassword	= "";
		$path				= $this->config->item("base_server_path").'application/views/esia/';
		$signFile			= $path.'signed'.uniqid(true).'.msg';
		$messageFile		= $path.'message'.uniqid(true).'.msg';

		file_put_contents($messageFile, $src);

		$certContent		= file_get_contents($this->config->item("cert_path").'wifi.sha256.crt');
		$cert				= openssl_x509_read($certContent);
		$keyContent			= file_get_contents($this->config->item("cert_path").'wifi.sha256.key');
		$privateKey			= openssl_pkey_get_private($keyContent, $privateKeyPassword);
		
		openssl_pkcs7_sign(
			$messageFile,
			$signFile,
			$cert,
			$privateKey,
			array()
		);

		if ( file_exists($signFile)) {
			$signed = file_get_contents($signFile);
			$signed = explode("\n\n", $signed);
			$sign   = str_replace("\n", "", $this->urlSafe($signed[3]));
			unlink($signFile);
		}
		if ( file_exists($messageFile)) {
			unlink($messageFile);
		}
		return $sign;
	}

	/* Parsers */

	/**
	* Prepares string for base64urlSafe-encoding
	* 
	* @param $string string
	* @return string
	*/
	private function urlSafe($string) {
		return rtrim(strtr(trim($string), '+/', '-_'), '=');
	}

	/**
	* Prepares a base64UrlSafe-encoded string and decodes it
	* 
	* @param $string string
	* @return string|false
	*/
	private function base64UrlSafeDecode($string) {
		$base64 = strtr($string, '-_', '+/');
		return base64_decode($base64);
	}

	/*
	* Parses a token for data contained in it
	* 
	* @param $accessToken string
	* @return array
	*/
	private function parseToken($accessToken) {
		$chunks			= explode('.', $accessToken);
		$output = array(
			'header'    => json_decode($this->base64UrlSafeDecode($chunks[0])),
			'payload'   => json_decode($this->base64UrlSafeDecode($chunks[1])),
			'signature' => $chunks[2],
			'hashpart'  => $chunks[0].".".$chunks[1],
		);
		$this->oid = $output['oid'] = $output['payload']->{"urn:esia:sbj_id"};
		$this->logmodel->addToLog("------------------\nParsed Access Token:\n------------------\n".print_r($output, true)."\n");
		return $output;
	}

	/*
	* Send a request for 
	* 
	* @param $accessToken string
	* @return array
	*/
	private function sendTokenRequest($request) {
		$options = array(
			'http' => array(
				'content' => http_build_query($request),
				'header'  => 'Content-type: application/x-www-form-urlencoded',
				'method'  => 'POST'
			)
		);
		$context  = stream_context_create($options);
		$result   = file_get_contents($this->userdatamodel->getURL('token'), false, $context);
		$result   = json_decode($result);
		$this->logmodel->addToLog("Request was sent sucsessfully. Server returned:\n".print_r($result, true));
		return $result;
	}

	/**
	* Return an URL we redirect an user to.
	* OR
	* Return a Codeigniter View with a link
	* 
	* @param $returnURLID int
	* @param $objectID int
	* @return string|false
	*/
	private function requestAuthCode($returnURLID = 0, $objectID = "c15aa69b-b10e-46de-b124-85dbd0a9f4c9") {
		// Извлечение конфигурации запроса к ЕСИА и критериев фильтрации
		$config      = json_decode(utf8_encode(file_get_contents($this->config->item("base_server_path")."tickets/".$objectID)));
		$this->scope = implode($this->dataProfile[$config->profile]["scopes"], " ");
		// (Методические рекомендации по использованию ЕСИА v 2.23, В.6.2.1 Стандартный режим запроса авторизационного кода)
		$timestamp   = date('Y.m.d H:i:s O');
		$this->state = $this->getState();
		$returnURL   = $this->config->item("base_url").'admin/getuserdata/'.$this->state."/".$returnURLID.'/'.$objectID;
		$secret      = $this->getSecret($this->scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
		$requestParams = array(
			'client_id'		=> $this->config->item("IS_MNEMONICS"),
			'client_secret'	=> $secret,
			'redirect_uri'	=> $returnURL,
			'scope'			=> $this->scope,
			'response_type'	=> 'code',
			'state'			=> $this->state,
			'timestamp'		=> $timestamp,
			'access_type'	=> 'offine'
		);
		$options = array(
			'url'        => $this->userdatamodel->getURL('code'),
			'get_params' => http_build_query($requestParams)
		);
		$this->logmodel->addToLog("Параметры запроса:\n".print_r($requestParams, true)."\n");
		$this->logmodel->addToLog("Содержимое ссылки на получение кода от ".$timestamp.":\n\"".$options['get_params']."\n");
		$this->logmodel->writeLog("esia_authcode.log");
		
		// return http_build_query($requestParams);
		// OR
		// in case we use Codeigniter
		// return to Codeigniter View
		return $this->load->view('esia/auth', $options, true);
	}

	/**
	* Return an object containing an access token
	* 
	* @return object|false
	*/
	private function getESIAToken($scope) {
		$timestamp   = date('Y.m.d H:i:s O');
		$this->state = $this->getState();
		$returnURL = $this->config->item("base_url").'admin/getuserdata';
		$secret    = $this->getSecret($scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
		
		$request   = array(
			'client_id'		=> $this->config->item("IS_MNEMONICS"),
			'code'			=> $this->input->get('code'),
			'grant_type'	=> 'authorization_code',
			'client_secret' => $secret,
			'state'			=> $this->state,
			'redirect_uri'	=> $returnURL,
			'scope'			=> $scope,
			'timestamp'		=> $timestamp,
			'token_type'	=> 'Bearer'
		);
		$this->logmodel->addToLog("REQUESTING TOKEN\nToken request @".$timestamp.":\n".print_r($request, true)."\n------------------\n");
		return $this->sendTokenRequest($request);
	}

	private function setTokens($profile) {
		foreach ($this->dataProfile[$profile]["scopes"] as $scope) {
			$this->{"token_".$scope}         = $this->getESIAToken( $scope );
			$this->{"token_".$scope."_data"} = $this->parseToken($this->{"token_".$scope}->access_token);
			if ( !$this->verifymodel->verifyToken($this->{"token_".$scope."_data"}) ) {
				return false;
			}
		}
		return true;
	}

	private function sendCallbackToClient($returnURLID, $backRequest) {
		if ( !$this->config->item('system_online') ){
			return false;
		}
		$result = false;
		$options = array(
			'http' => array(
				'content' => http_build_query($backRequest),
				'header'  => 'Content-type: application/x-www-form-urlencoded',
				'method'  => 'POST'
			)
		);
		$context = stream_context_create($options);
		$urls    = $this->config->item('returnURLS');
		$url     = $urls[$returnURLID];
		$result  = file_get_contents($url, false, $context);
		if ($result === FALSE) {
			$this->logmodel->addToLog( "CALLBACK REQUEST TO ".$url." FAILED OR SYSTEM NOW OFFLINE!\n" );
			$this->logmodel->writeLog();
			return false;
		}
		return $result;
	}

	/* MAIN SECTION GETTER*/

	/**
	* redirection
	*/
	public function index () {
		//print "No more..";
		//return false;
		print $this->requestAuthCode();
	}

	public function processticket() {
		if (   !$this->input->post("ticket")
			|| !$this->input->post("data")
			|| !$this->input->post("systemID")
			|| !strlen($this->input->post("ticket"))
			|| !strlen($this->input->post("data"))
			|| !strlen($this->input->post("systemID"))
			) {
			$this->logmodel->addToLog("A REQUIRED FIELD: POST['data'] or POST['ticket'] IS MISSING OR EMPTY\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		$data = json_decode($this->input->post("data"));
		if ( !$data ) {
			$this->logmodel->addToLog("SEARCH PATTERN COULD NOT BE PARSED AS VALID JSON\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		$URLs = $this->config->item('returnURLS');
		if ( !isset($URLs[$this->input->post("systemID")]) ) {
			$this->logmodel->addToLog("SYSTEM ID: ".$this->input->post("systemID")." NOT FOUND\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}

		if( FALSE === file_put_contents($this->config->item("base_server_path")."tickets/".$this->input->post("ticket"), $this->input->post("data"))) {
			$this->logmodel->addToLog("A TICKET COULD NOT BE WRITTEN\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		$this->logmodel->addToLog("A TICKET WAS PROCESSED SUCCESFULLY\n");
		$this->logmodel->writeLog("esia_ticket.log");
		print $this->requestAuthCode($returnURLID = 0, $this->input->post("ticket"));
		return true;
	}

	private function getUserDataObject() {
		return array(
			'oid'			=> $this->oid,
			'trusted'		=> $this->userdatamodel->trusted,
			'fullname'		=> $this->userdatamodel->fullname,
			'birthplace'	=> $this->userdatamodel->birthplace,
			'cellphone'		=> $this->userdatamodel->cel_ph,
			'email'			=> $this->userdatamodel->email,
			'birthplace'	=> $this->userdatamodel->birthplace,
			'prg'			=> array(
				'region'	=> $this->userdatamodel->reg_region,
				'city'		=> $this->userdatamodel->reg_city,
				'street'	=> $this->userdatamodel->reg_street,
				'house'		=> $this->userdatamodel->reg_house,
				'frame'		=> $this->userdatamodel->reg_frame,
				'flat'		=> $this->userdatamodel->reg_flat,
				'fias'		=> $this->userdatamodel->reg_fias
			),
			'plv'			=> array(
				'region'	=> $this->userdatamodel->plv_region,
				'city'		=> $this->userdatamodel->plv_city,
				'street'	=> $this->userdatamodel->plv_street,
				'house'		=> $this->userdatamodel->plv_house,
				'frame'		=> $this->userdatamodel->plv_frame,
				'flat'		=> $this->userdatamodel->plv_flat,
				'fias'		=> $this->userdatamodel->plv_fias
			)
		);
	}

	private function userDeniedAccess() {
		if ( $this->input->get('error') ) {
			$errorRequest = array(
				'ticket'      => $objectID,
				'error'       => $this->input->get('error'),
				'description' => $this->input->get('error_description')
			);
			$this->logmodel->addToLog( "USER DENIED ACCESS" );
			//print_r($errorRequest);
			$this->sendCallbackToClient($returnURLID, $errorRequest);
			$this->logmodel->writeLog();
			return false;
		}
	}

	/**
	* Calls a function requesting User Data
	*
	* @param $state string
	* @param $returnURLID int
	* @param $objectID int
	* @return true|false
	*/
	public function getuserdata($state = "", $returnURLID = 0, $objectID = 0 ) {
		if ( !$this->verifymodel->verifyState($state) ) {
			$this->load->helper("url");
			redirect("/");
			return false;
		}
		if ( $this->userDeniedAccess() ) {
			print "User Denied Access To Some Data";
			$this->load->helper("url");
			redirect("/");
			return false;
		}
		//var_dump($this->input->get('code'));

		if ( strlen($this->input->get('code')) ) {
			$config = json_decode(utf8_encode(file_get_contents($this->config->item("base_server_path")."tickets/".$objectID)));
			if ( $this->setTokens($config->profile) ) {
				// если удалось получить и проверить все токены:
				foreach ($this->dataProfile[$config->profile]["requests"] as $request) {
					$scope = $this->rTokens[$request];
					$this->userdatamodel->requestUserData($this->{"token_".$scope}->access_token, $request);
				}

				$userdata = $this->getUserDataObject();
				$this->logmodel->addToLog( "\n------------------\nUSER DATA SET:\n".print_r($userdata, true)."\n" );

				$backRequest = array(
					'oid'      => $userdata['oid'],
					'ticket'   => $objectID,
					'valid'    => $this->userdatamodel->processUserMatching($userdata, $objectID, $config->profile),
					'trusted'  => $userdata['trusted']
				);
				print_r($userdata);
				print "<br><br>";
				print_r($backRequest);

				$this->sendCallbackToClient($returnURLID, $backRequest);
				$this->logmodel->addToLog( "\nCOMPLETED SUCCESSFULLY!\n" );
				$this->logmodel->writeLog();
				return true;
			}
			$this->logmodel->addToLog( "\nUNABLE TO COLLECT REQUIRED ACCESS TOKENS!\n" );
		}
		$this->logmodel->addToLog( "Authorization Code was not provided" );
		$this->logmodel->writeLog();
		return false;
	}

	/*
	public function writeTokenFile() {
		$objectID = "c15aa69b-b10e-46de-b124-85dbd0a9f4c9";
		
		$file   = file_get_contents($this->config->item("base_server_path")."tickets/".$objectID);
		$config = json_decode($file);

		$ticket = array(
			"profile"     => "address",
			"matchParams" => array(
				"region"  => "Архангельская обл",
				"city"    => array(
					"г Архангельск"   => array(
						"ул Гагарина" => array("4","3","7","32","9","10"),
						"ул Ленина"   => array("4","3","7","5","9","10")
					),
					"г Северодвинск" => array()
				)
			)
		);
		$json = json_encode($ticket);
		print $json;
		$file   = file_put_contents($this->config->item("base_server_path")."tickets/".$objectID, $json);
	}
	*/
}
?>