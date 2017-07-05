<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Admin extends CI_Controller {
	/* Многие пожелания добра:
	*  https://github.com/fr05t1k/esia/blob/master/src/OpenId.php
	*  https://habrahabr.ru/post/276313/
	*
	*  DO: complete $this->getuserdata()
	       multiscope user data requests
	*      code the correct signature check
	*/

	function __construct() {
		parent::__construct();
	}

	private $state          = null;
	private $parsedToken    = null;
	private $oid            = null;
	private $tlog           = null;
	private $logMode        = 'logfile'; //both, none, logfile, screen
	private $portalUrl      = 'https://esia-portal1.test.gosuslugi.ru/';
	private $personUrl      = 'rs/prns';
	private $codeUrl        = 'aas/oauth2/ac';
	private $tokenUrl       = 'aas/oauth2/te';
	private $scope          = 'fullname';
	//private $dataCollection = array(); // for multiscope user data requests

	/*  URL Retrieve  */

	/**
	* Returns an URL for an authorization code
	*
	* @return string
	*/
	private function getCodeUrl() {
		return $this->portalUrl.$this->codeUrl."?";
	}

	/**
	* Return an URL for an access token
	*
	* @return string
	*/
	private function getTokenUrl() {
		return $this->portalUrl.$this->tokenUrl;
	}

	/**
	* Return an URL for an user data
	*
	* @return string
	*/
	private function getPersonUrl() {
		return $this->portalUrl.$this->personUrl;
	}

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
	* @throws SignFailException
	*/
	private function getSecret($src) {
		$sign				= null;
		$privateKeyPassword	= "";
		$path				= $this->config->item("base_server_path").'application/views/esia/';
		$signFile			= $path.'signed'.uniqid(true).'.msg';
		$messageFile		= $path.'message'.uniqid(true).'.msg';

		file_put_contents($messageFile, $src);

		$certContent		= file_get_contents($path.'cert/self/wifi.sha256.crt');
		$cert				= openssl_x509_read($certContent);
		$keyContent			= file_get_contents($path.'cert/self/wifi.sha256.key');
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
		$this->addToLog("------------------\nParsed Access Token:\n------------------\n".print_r($output, true)."\n");
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
		$result   = file_get_contents($this->getTokenUrl(), false, $context);
		$result   = json_decode($result);
		$this->addToLog("Request was sent sucsessfully. Server returned:\n".print_r($result, true));
		return $result;
	}

	/* Logging */

	/**
	* Forms a logFile string depending on log mode
	* 
	* @param $logFile none|logfile|screen|both
	* @return string
	*/
	private function addToLog($message) {
		if ($this->logMode === "logfile" || $this->logMode === "both") {
			$this->tlog .= $message;
		}
		if ($this->logMode === "screen" || $this->logMode === "both") {
			print nl2br(str_replace(" ", "&nbsp;", $message));
		}
		return true;
	}

	/**
	* Writes a log to a specified or default file location
	* 
	* @param $logFile string
	* @return string
	*/
	private function writeLog($logFile="") {
		$file = $this->config->item("base_server_path")."esialog.log";
		if ( strlen($logFile) ) {
			$file = $this->config->item("base_server_path").$logFile;
		}
		$open = fopen($file, "w");
		fputs($open, $this->tlog);
		fclose($open);
	}

	/* VERIFICATION */

	/**
	* Verifies an access token
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifyToken($accessToken) {
		// проверка токена ( Методические рекомендации по использованию ЕСИА v 2.23, Приложение В.6.4)
		$this->addToLog("TOKEN VERIFICATION\n");
		if ( !$this->verifySignature($accessToken) ) {// ................. check signature !!
			return false;
		}
		if ( !$this->verifyMnemonics($accessToken['payload'])) {
			return false;
		};
		if ( !$this->verifyExpiration($accessToken['payload'])) {
			return false;
		};
		if ( !$this->verifyIssuer($accessToken['payload'])) {
			return false;
		};
		return true;
	}

	/**
	* Verifies a token issuer
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifyIssuer($accessToken) {
		if ($accessToken->iss === "http://esia.gosuslugi.ru/") {
			return true;
		}
		$this->addToLog("\nToken issuer forged!\n");
		return false;
	}

	/**
	* Verifies a mnemonics sent by ESIA to be a system of ours
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifyMnemonics($accessToken) {
		if ( !isset($accessToken->client_id) && $accessToken->client_id !== $this->config->item("IS_MNEMONICS") ) {
			$this->addToLog("MNEMONICS: <b>".$accessToken->client_id." - DO NOT MATCH!</b>\n");
			return false;
		}
		$this->addToLog("MNEMONICS: <b>CORRECT</b>\n");
		return true;
	}

	/**
	* Verifies a token sent by ESIA whether it is applicable
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifyExpiration($accessToken) {
		$timeTolerance = 60; // 1 sec can cause failure.
		if ( (int) date("U") < (int) ($accessToken->nbf - $timeTolerance) || (int) date("U") > (int) $accessToken->exp ) {
			$this->addToLog("ACTUAL: <b>NO!</b>\nNBF: ".$accessToken->nbf - $timeTolerance."( -".$timeTolerance." sec.),\nNOW: ".date("U").",\nEXP: ".$accessToken->exp."\n");
			return false;
		}
		$this->addToLog("ACTUAL: <b>YES, BIAS: ".(date("U") - (int) $accessToken->nbf)." sec. (-".$timeTolerance." sec. tolerance)</b>\n");
		return true;
	}

	/**
	* Verifies a signature sent by ESIA
	* disabled
	* 
	* @param $accessToken array
	* @return true|false
	*/
	private function verifySignature($accessToken) { // correct it later
		return true;
		$algs = array(
			'RS256' => 'sha256'
		);
		
		$hash = $this->getSecret("HEADER.PAYLOAD");
		if ( $hash === $accessToken['signature'] ) {
			$this->addToLog("SIGNATURE: MATCHED OK!\n");
			return true;
		}
		$this->addToLog( "<b>COMPUTED SIGNATURE HASH</b>:<br>\n".$hash."\n<br>DOES NOT MATCH <b>ENCLOSED TOKEN HASH</b>:<br>\n".$accessToken['signature']."<br>\n------------------\n" );
		return false;
	}

	/**
	* Verifies state previously given in return URL with the one provided by us
	* 
	* @param $state string
	* @return string|false
	*/
	private function verifyState($state="") {
		// проверка возвращённого кода состояния ( Методические рекомендации по использованию ЕСИА v 2.23, Приложение В.2.2)
		if ( !strlen($state) ) {
			return false;
		}
		if ( $this->input->get('state') === $state ) {
			return true;
		}
		return false;
	}

	/* DATA GETTERS */

	/**
	* Returns User Data object contents
	* 
	* @param $token string
	* @return string|false
	*/
	private function requestUserData($token="") {
		if ( !strlen($token) ) {
			$this->addToLog("Access token is missing. Aborting\n");
			return false;
		}
		if ( !strlen($this->oid) ) {
			$this->addToLog("Object ID is missing. Aborting\n");
			return false;
		}
		$url = $this->getPersonUrl()."/".$this->oid;
		$options = array(
			'http' => array(
				'max_redirects' => 1,
				'ignore_errors' => 1, // WTF???
				'header' => 'Authorization: Bearer '.$token,
				'method'  => 'GET'
			)
		);
		$context = stream_context_create($options);
		$result  = json_decode(file_get_contents($url, false, $context));
		print nl2br(str_replace(" ", "&nbsp;", print_r($result, true)));
		//return $result;
		$this->addToLog("\n------------------#-#-#------------------\nRequesting User Data\n");
		$this->addToLog(print_r($result, true));
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
	private function requestAuthCode($returnURLID = 0, $objectID = 0) {
		//( Методические рекомендации по использованию ЕСИА v 2.23, В.6.2.1 Стандартный режим запроса авторизационного кода)
		$options = array(
			'url' => $this->getCodeUrl()
		);
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
			'access_type'	=> 'online'
		);
		$options['get_params'] = http_build_query($requestParams);
		$this->addToLog("Параметры запроса:\n".print_r($requestParams, true)."\n");
		$this->addToLog("Содержимое ссылки на получение кода от ".$timestamp.":\n\"".$options['get_params']."\n");
		$this->writeLog("ac_request.log");
		
		// return http_build_query($requestParams);
		// OR
		// in case we use Codeigniter
		// return to Codeigniter View
		$this->load->view('esia/auth', $options);
	}

	/**
	* Return an object containing an access token
	* 
	* @return object|false
	*/
	private function getESIAToken() {
		$timestamp   = date('Y.m.d H:i:s O');
		$this->state = $this->getState();
		$returnURL = $this->config->item("base_url").'admin/getuserdata';
		$secret    = $this->getSecret($this->scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
		
		$request   = array(
			'client_id'		=> $this->config->item("IS_MNEMONICS"),
			'code'			=> $this->input->get('code'),
			'grant_type'	=> 'authorization_code',
			'client_secret' => $secret,
			'state'			=> $this->state,
			'redirect_uri'	=> $returnURL,
			'scope'			=> $this->scope,
			'timestamp'		=> $timestamp,
			'token_type'	=> 'Bearer'
		);
		$this->addToLog("REQUESTING TOKEN\nToken request @".$timestamp.":\n".print_r($request, true)."\n------------------\n");
		return $this->sendTokenRequest($request);
	}

	/* MAIN SECTION GETTER*/

	/**
	* redirection
	*/
	public function index () {
		$this->requestAuthCode();
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
		if ( !$this->verifyState($state) ) {
			$this->addToLog("\nSERVER RETURNED STATE PARAMETER '".$this->input->get('state')."' WHICH DOES NOT MATCH THE ONE SUPPLIED! Aborting!\n------------------");
			$this->writeLog();
			return false;
		}
		// Codeigniter-style verification
		if ( $this->input->get('code') ) {
			$tokenData   = $this->getESIAToken();
			$parsedToken = $this->parseToken($tokenData->access_token);
			if ($this->verifyToken($parsedToken)) {
				// this, actually, shall be a return value:
				$this->requestUserData($tokenData->access_token);
			}
			$this->writeLog();
			return true;
		}
		$this->addToLog( "Authorization Code was not provided" );
		$this->writeLog();
		return false;
	}
}
?>