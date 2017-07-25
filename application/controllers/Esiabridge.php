<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Esiabridge extends CI_Controller {
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
		$file = $this->config->item("base_server_path")."tickets/".$objectID;
		if ( !file_exists($file) ) {
			$this->logmodel->addToLog("No valid config file supplied\n");
			$this->logmodel->writeLog("esia_authcode.log");
		}
		$config      = json_decode(file_get_contents($file));
		if ( !isset($this->dataProfile[$config->profile]) ) {
			$this->logmodel->addToLog("Profile is unknown\n");
			$this->logmodel->writeLog("esia_authcode.log");
			print "Error while getting authorization code";
			return false;
		}
		$this->scope = implode($this->dataProfile[$config->profile]["scopes"], " ");
		// (Методические рекомендации по использованию ЕСИА v 2.23, В.6.2.1 Стандартный режим запроса авторизационного кода)
		$timestamp   = date('Y.m.d H:i:s O');
		$this->state = $this->getState();
		$returnURL   = $this->config->item("base_url").'esiabridge/token/'.$this->state."/".$returnURLID.'/'.$objectID;
		$secret      = $this->getSecret($this->scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
		$requestParams = array(
			'client_id'		=> $this->config->item("IS_MNEMONICS"),
			'cid'			=> $this->config->item("IS_MNEMONICS"),
			'rurl'			=> "http://esia.arhcity.ru/redirect",
			'client_secret'	=> $secret,
			'redirect_uri'	=> $returnURL,
			'scope'			=> $this->scope,
			'response_type'	=> 'code',
			'state'			=> $this->state,
			'timestamp'		=> $timestamp,
			'access_type'	=> 'online'
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
		//return $this->load->view('esia/auth', $options, true);
		return $options['url'].$options['get_params'];
	}

	/**
	* Return an object containing an access token
	* 
	* @return object|false
	*/
	private function getESIAToken($scope) {
		$timestamp   = date('Y.m.d H:i:s O');
		$this->state = $this->getState();
		$returnURL   = $this->config->item("base_url").'esiabridge/token';
		$secret      = $this->getSecret($scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
		
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
	/**
	* Sets an access token depending on profile
	* 
	* @return true|false
	*/
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

	/**
	* Send a callback to a client system with authentication result
	* 
	* @return string|false
	*/
	private function sendCallbackToClient($returnURLID, $backRequest) {
		if ( !$this->config->item('system_online') ){
			$this->logmodel->addToLog( "System is now offline! Check config.\n" );
			$this->logmodel->writeLog();
			return false;
		}
		$options = array(
			'http' => array(
				'content' => http_build_query($backRequest),
				'header'  => 'Content-type: application/x-www-form-urlencoded',
				'method'  => 'POST'
			)
		);
		$context = stream_context_create($options);
		$urls    = $this->config->item('returnURLS');
		if (!isset($urls[$returnURLID])) {
			$this->logmodel->addToLog( "No return URL found by specified index. Check config.\n" );
			$this->logmodel->writeLog();
			return false;
		}
		$url     = $urls[$returnURLID];
		$result  = file_get_contents($url, false, $context);
		//var_dump($http_response_header);
		$location = false;
		foreach ( $http_response_header as $header ) {
			if ( preg_match("/Location:(.*)/i", $header, $matches) ) {
				$location = trim($matches[1]);
			}
		}
		if ($result === FALSE) {
			$this->logmodel->addToLog( "Callback request to ".$url." failed! Check config.\n" );
			$this->logmodel->writeLog();
			return false;
		}
		return $location;
	}

	/* MAIN SECTION GETTER*/

	/**
	* redirection
	*/
	public function index () {
		header("Location: http://www.arhcity.ru");
		//print "No more..";

		return false;
		//print '<a href="'.$this->requestAuthCode().'">Вход через ЕСИА</a>';
	}

	private function checkClientSystem(){
		$urls = $this->config->item('returnURLS');
		if ( isset($urls[$this->input->post("systemID")]) ) {
			return true;
		}
		$this->logmodel->addToLog("System ID: ".$this->input->post("systemID")." not found\n");
		$this->logmodel->writeLog("esia_ticket.log");
		return false;
	}

	private function writeTicket($data) {
		$ticketPath = $this->config->item("base_server_path")."tickets/".$this->input->post("ticket");
		if ( file_put_contents($ticketPath, json_encode($data)) === FALSE ) {
			$this->logmodel->addToLog("A ticket file could not be written\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		return true;
	}

	private function parseTicketData() {
		$data = json_decode($this->input->post("data"));
		if ( !$data ) {
			$this->logmodel->addToLog("Search pattern could not be parsed as valid JSON\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}
		return $data;
	}

	public function processticket() {
		//print_r($this->input->post());
		if (   !$this->input->post("ticket")
			|| !$this->input->post("data")
			|| !$this->input->post("systemID")
			|| !strlen($this->input->post("ticket"))
			|| !strlen($this->input->post("data"))
			|| !strlen($this->input->post("systemID"))
			) {
			$this->logmodel->addToLog("At least one of an essential fields: POST['data'] or POST['ticket'] or POST['systemID'] is missing or empty\n");
			$this->logmodel->writeLog("esia_ticket.log");
			return false;
		}

		if ( !$this->checkClientSystem() ) {
			return false;
		}
		
		$ticketData = $this->parseTicketData();

		if ( !$ticketData || !$this->writeTicket($ticketData) ) {
			return false;
		}

		$this->logmodel->addToLog("A ticket was processed succesfully\n");
		$this->logmodel->writeLog("esia_ticket.log");
		print $this->requestAuthCode( $this->input->post("systemID"), $this->input->post("ticket"));
		return true;
	}

	private function getUserDataObject() {
		return array(
			'oid'			=> $this->oid,
			'trusted'		=> $this->userdatamodel->trusted,
			'fullname'		=> $this->userdatamodel->fullname,
			'birthplace'	=> $this->userdatamodel->birthplace,
			'cellphone'		=> $this->userdatamodel->cellPhone,
			'email'			=> $this->userdatamodel->email,
			'prg'			=> array(
				'region'	=> $this->userdatamodel->regRegion,
				'city'		=> $this->userdatamodel->regCity,
				'street'	=> $this->userdatamodel->regStreet,
				'house'		=> $this->userdatamodel->regHouse,
				'frame'		=> $this->userdatamodel->regFrame,
				'flat'		=> $this->userdatamodel->regFlat,
				'fias'		=> $this->userdatamodel->regFias
			),
			'plv'			=> array(
				'region'	=> $this->userdatamodel->plvRegion,
				'city'		=> $this->userdatamodel->plvCity,
				'street'	=> $this->userdatamodel->plvStreet,
				'house'		=> $this->userdatamodel->plvHouse,
				'frame'		=> $this->userdatamodel->plvFrame,
				'flat'		=> $this->userdatamodel->plvFlat,
				'fias'		=> $this->userdatamodel->plvFias
			)
		);
	}

	private function userDeniedAccess($returnURLID, $objectID) {
		if ( $this->input->get('error') ) {
			$errorRequest = array(
				'ticket'      => $objectID,
				'error'       => $this->input->get('error'),
				'description' => $this->input->get('error_description')
			);
			$this->logmodel->addToLog( "USER DENIED ACCESS" );
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
	public function token($state = "", $returnURLID = 0, $objectID = 0 ) {
		$urls = $this->config->item("returnURLS");
		if ( !$this->verifymodel->verifyState($state) || $this->userDeniedAccess($returnURLID, $objectID) ) {
			$this->load->helper("url");
			redirect(strstr($urls[$returnURLID],"&",TRUE));
			return false;
		}

		if ( strlen($this->input->get('code')) ) {
			$ticket_file = $this->config->item("base_server_path")."tickets/".$objectID;
			if (!file_exists($ticket_file)) {
				$this->logmodel->addToLog( "\nUnable to read ticket file!\n" );
				return false;
			}
			$config = json_decode(file_get_contents($ticket_file));
			if ( $this->setTokens($config->profile) ) {
				// если удалось получить и проверить все токены:
				foreach ($this->dataProfile[$config->profile]["requests"] as $request) {
					$scope = $this->rTokens[$request];
					$this->userdatamodel->requestUserData($this->{"token_".$scope}->access_token, $request);
				}

				$userdata = $this->getUserDataObject();
				$this->logmodel->addToLog( "\n------------------\nUSER DATA SET:\n".print_r($userdata, true)."\n" );
				$sendData = array();
				if ($config->profile === "fullname") {
					$sendData = $userdata['fullname'];
				}
				if ($config->profile === "fulldata") {
					$sendData = $userdata;
				}
				$backRequest = array(
					'oid'      => $userdata['oid'],
					'ticket'   => $objectID,
					'data'     => json_encode($sendData),
					'valid'    => $this->userdatamodel->processUserMatching($userdata, $objectID, $config->profile),
					'trusted'  => $userdata['trusted']
				);
				//print_r($userdata);
				//print "<br><br>";
				//print_r($backRequest);

				$result      = $this->sendCallbackToClient($returnURLID, $backRequest);
				if ( file_exists($ticket_file) ) {
					unlink($ticket_file);
				}
				$this->logmodel->addToLog( "\nCOMPLETED SUCCESSFULLY!\n" );
				$this->logmodel->writeLog();
				$this->load->helper('url');
				//var_dump($result);
				if ( $result ) {
					redirect( $result );
					return true;
				}
				redirect($urls[$returnURLID]);
				return true;
			}
			$this->logmodel->addToLog( "\nUNABLE TO COLLECT REQUIRED ACCESS TOKENS!\n" );
		}
		$this->logmodel->addToLog( "Authorization Code was not provided" );
		$this->logmodel->writeLog();
		return false;
	}
}
?>