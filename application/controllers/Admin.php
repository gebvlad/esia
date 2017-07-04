<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Admin extends CI_Controller {
	/* Многие пожелания добра:
	*  https://github.com/fr05t1k/esia/blob/master/src/OpenId.php
	*  https://habrahabr.ru/post/276313/
	*
	*  TODO: multiscope user data requests
	*        code the correct signature check
	*/

	function __construct() {
		parent::__construct();
	}

	private $state          = null;
	private $parsedToken    = null;
	private $access_token   = null;
	private $oid            = null;
	private $code           = null;
	private $tlog           = null;
	private $logMode        = 'logfile'; //both, none, logfile, screen
	private $portalUrl      = 'https://esia-portal1.test.gosuslugi.ru/';
	private $personUrl      = 'rs/prns';
	private $codeUrl        = 'aas/oauth2/ac';
	private $tokenUrl       = 'aas/oauth2/te';
	private $scope          = 'fullname';
	private $dataCollection = array(); // for multiscope user data requests

	/*  URL Retrieve  */
	private function getCodeUrl() {
		return $this->portalUrl.$this->codeUrl;
	}

	private function getTokenUrl() {
		return $this->portalUrl.$this->tokenUrl;
	}

	private function getPersonUrl() {
		return $this->portalUrl.$this->personUrl;
	}
	/* Cryptografic & hash function wrappers */
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
		
		$signResult = openssl_pkcs7_sign(
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
	private function urlSafe($string) {
		return rtrim(strtr(trim($string), '+/', '-_'), '=');
	}

	private function base64UrlSafeDecode($string) {
		$base64 = strtr($string, '-_', '+/');
		return base64_decode($base64);
	}

	private function parseToken($accessToken) {
		$chunks			= explode('.', $accessToken);
		$output = array(
			'header'    => json_decode($this->base64UrlSafeDecode($chunks[0])),
			'payload'   => json_decode($this->base64UrlSafeDecode($chunks[1])),
			'signature' => $chunks[2],
			'hashpart'  => $chunks[0].".".$chunks[1]
		);
		$this->oid = $output['payload']->{"urn:esia:sbj_id"};
		$this->addToLog("--------------\nParsed Access Token:\n--------------\n".print_r($output, true)."\n");
		return $output;
	}
	
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
		$this->addToLog("Request sent sucsessfully. The server returned:\n".print_r($result, true));
		return $result;
	}
	/* Logging */
	private function addToLog($message) {
		if ($this->logMode === "logfile" || $this->logMode === "both") {
			$this->tlog .= $message;
		}
		if ($this->logMode === "screen" || $this->logMode === "both") {
			print nl2br(str_replace(" ", "&nbsp;", $message));
		}
		return true;
	}
	
	private function writeLog($logFile="") {
		$file = $this->config->item("base_server_path")."esialog.log";
		if ( strlen($logFile) ) {
			$file = $this->config->item("base_server_path").$logFile;
		}
		$open = fopen($file, "w");
		fputs($open, $this->tlog);
		fclose($open);
	}
	#
	#	Verification:
	#
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
		if ( !$this->verifyTarget($accessToken['payload'])) {
			return false;
		};
		return true;
	}

	private function verifyTarget($accessToken) {
		if ($accessToken->iss === "http://esia.gosuslugi.ru/") {
			return true;
		}
		$this->addToLog("\nToken issuer forged!\n");
		return false;
	}

	private function verifyMnemonics($accessToken) {
		if ( !isset($accessToken->client_id) && $accessToken->client_id !== $this->config->item("IS_MNEMONICS") ) {
			$this->addToLog("MNEMONICS: <b>".$accessToken->client_id." - DO NOT MATCH!</b>\n");
			return false;
		}
		$this->addToLog("MNEMONICS: <b>CORRECT</b>\n");
		return true;
	}

	private function verifyExpiration($accessToken) {
		$timeTolerance = 60; // 1 sec can cause failure.
		if ( (int) date("U") < (int) ($accessToken->nbf - $timeTolerance) || (int) date("U") > (int) $accessToken->exp ) {
			$this->addToLog("ACTUAL: <b>NO!</b>\nNBF: ".$accessToken->nbf - $timeTolerance."( -".$timeTolerance." sec.),\nNOW: ".date("U").",\nEXP: ".$accessToken->exp."\n");
			return false;
		}
		$this->addToLog("ACTUAL: <b>YES, BIAS: ".(date("U") - (int) $accessToken->nbf)." sec. (-".$timeTolerance." sec. tolerance)</b>\n");
		return true;
	}

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
		$this->addToLog( "<b>COMPUTED SIGNATURE HASH</b>:<br>\n".$hash."\n<br>DOES NOT MATCH <b>ENCLOSED TOKEN HASH</b>:<br>\n".$accessToken['signature']."<br>\n---------------\n" );
		return false;
	}

	private function verifyState($state) {
		// проверка возвращённого кода состояния ( Методические рекомендации по использованию ЕСИА v 2.23, Приложение В.2.2)
		if ( $_GET['state'] === $state) {
			return true;
		}
		return false;
	}

	/* DATA GETTERS */
	private function requestuserdata($token) { // FINAL REQUEST (it's a kind of magic that i have guessed the correct way!)
		$this->addToLog("\n-----------------#-#-#-------------------------\nRequesting User Data\n");
		$url = $this->getPersonUrl()."/".$this->oid;

		$options = array(
			'http' => array(
				'max_redirects' => 1, // WTF???
				'ignore_errors' => 1, // WTF???
				'header' => 'Authorization: Bearer '.$token,
				'method'  => 'GET'
			)
		);
		$context = stream_context_create($options);
		$result  = file_get_contents($url, false, $context);

		$this->addToLog(print_r($result, true));
		print nl2br(str_replace(" ", "&nbsp;", print_r(json_decode($result), true)));
		//return $result;
	}


	private function requestcode($returnURLID = 0, $objectID = 0) {
		//( Методические рекомендации по использованию ЕСИА v 2.23, В.6.2.1 Стандартный режим запроса авторизационного кода)
		$options = array(
			'url' => $this->getCodeUrl()."?"
		);
		$timestamp = date('Y.m.d H:i:s O');
		$this->state     = $this->getState();
		$returnURL = $this->config->item("base_url").'admin/getesiatoken/'.$this->state."/".$returnURLID.'/'.$objectID;
		$secret    = $this->getSecret($this->scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
		$request_params = array(
			'client_id'		=> $this->config->item("IS_MNEMONICS"),		//good
			'client_secret'	=> $secret,
			'redirect_uri'	=> $returnURL,				//good
			'scope'			=> $this->scope,			//good
			'response_type'	=> 'code',					//good
			'state'			=> $this->state,			//good
			'timestamp'		=> $timestamp,				//good
			'access_type'	=> 'online',				//good
		);
		$this->addToLog("Параметры запроса:\n".print_r($request_params, true)."\n");
		$options['get_params']  = http_build_query($request_params);
		$this->addToLog("\nСодержимое ссылки на получение кода от ".$timestamp.":\n\"".$options['get_params']."\n");
		$this->writeLog("ac_request.log");
		$this->load->view('esia/auth', $options);
	}

	/* MAIN SECTION GETTER*/
	public function index () {
		$this->requestcode();
	}

	public function getesiatoken($state="", $returnURLID = 0, $objectID = 0 ) {
		if ( isset($_GET['code']) ) {
			$this->addToLog("Requesting token. See logs for details\n", true);
			$timestamp   = date('Y.m.d H:i:s O');
			$this->state = $this->getState();

			if (!$this->verifyState($state)) {
				$this->addToLog("\nSERVER RETURNED STATE PARAMETER '".$_GET['state']."' WHICH DOES NOT MATCH THE ONE SUPPLIED! Aborting!\n---------------------------------");
				$this->writeLog();
				return false;
			}

			$returnURL = $this->config->item("base_url").'admin/getesiatoken';
			$secret    = $this->getSecret($this->scope.$timestamp.$this->config->item("IS_MNEMONICS").$this->state);
			
			$request   = array(
				'client_id'		=> $this->config->item("IS_MNEMONICS"),
				'code'			=> $_GET['code'],
				'grant_type'	=> 'authorization_code',
				'client_secret' => $secret,
				'state'			=> $this->state,
				'redirect_uri'	=> $returnURL,
				'scope'			=> $this->scope,
				'timestamp'		=> $timestamp,
				'token_type'	=> 'Bearer'
			);
			$this->addToLog("\n\nToken request @".$timestamp.":\n".print_r($request, true)."\n---------------------------------\n");
			$result = $this->sendTokenRequest($request);
			$this->parsedToken = $this->parseToken($result->access_token);
			if ($this->verifyToken($this->parsedToken)) {
				$data = $this->requestuserdata($result->access_token);
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