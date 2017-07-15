<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Userdatamodel extends CI_Model {

	function __construct() {
		parent::__construct();
	}


	public $fullname       = null;
	public $regRegion     = null;
	public $regCity       = null;
	public $regStreet     = null;
	public $regHouse      = null;
	public $regFrame      = null;
	public $regFlat       = null;
	public $regFias       = null;
	public $plvRegion     = null;
	public $plvCity       = null;
	public $plvStreet     = null;
	public $plvHouse      = null;
	public $plvFrame      = null;
	public $plvFlat       = null;
	public $plvFias       = null;
	public $birthplace     = null;
	public $email          = null;
	public $cellPhone      = null;
	public $trusted        = null;

	/*  URL Retrieve  */

	/**
	* Returns an URL specified by $URLType
	* @param string $URLType: code|token|fullname|birthplace|address|contacts|openid
	* @return string
	*/
	public function getURL($urlType='name') {
		$urls = array(
			'code'       => 'aas/oauth2/ac?',
			'token'      => 'aas/oauth2/te',
			'fullname'   => 'rs/prns/'.$this->oid,
			'birthplace' => 'rs/prns/'.$this->oid,
			'address'    => 'rs/prns/'.$this->oid.'/addrs',
			'contacts'   => 'rs/prns/'.$this->oid.'/ctts',
			'openid'     => 'rs/prns/'.$this->oid
		);
		return $this->portalUrl.$urls[$urlType];
	}

	/* DATA GETTERS */

	/**
	* Returns contents of User Data object 
	* 
	* @param $token string
	* @return false
	*/
	public function requestUserData($token="", $mode = 'fullname') {

		if ( !$this->checkForTokenAndOID($token) ) {
			return false;
		}
		$this->logmodel->addToLog("\n------------------#-#-#------------------\nRequesting User Data\n");

		$url = $this->getURL($mode);
		$result  = json_decode(file_get_contents($url, false, $this->getRequestContext($token)));

		$this->logmodel->addToLog("\nUser data request success\n".print_r($result, true));
		
		if ($mode === 'birthplace') {
			$this->birthplace = $result->birthPlace;
		}

		if ($mode === 'fullname') {
			$this->fullname = implode( array($result->lastName, $result->firstName, $result->middleName), " " );
		}

		if ( isset( $result->trusted ) ) {
			$this->trusted = ($result->trusted) ? 1 : 0;
		}

		if ( isset( $result->elements ) ) {
			$this->requestUserDocs($result->elements, $token);
		}
	}


	/**
	* Returns context for User Data request
	* 
	* @param $token string
	* @return resource
	*/
	private function getRequestContext($token) {
		return stream_context_create(array(
			'http' => array(
				'max_redirects' => 1,
				'ignore_errors' => 1, // WTF???
				'header'        => 'Authorization: Bearer '.$token,
				'method'        => 'GET'
			)
		));
	}

	/**
	* Returns a partial user dataset
	* 
	* @param $result object
	* @return resource
	*/
	private function setPRGDataset($result) {
		$this->regRegion = (isset($result->region))   ? $result->region   : 0 ;
		$this->regCity   = (isset($result->city))     ? $result->city     : 0 ;
		$this->regStreet = (isset($result->street))   ? $result->street   : 0 ;
		$this->regHouse  = (isset($result->house))    ? $result->house    : 0 ;
		$this->regFrame  = (isset($result->frame))    ? $result->frame    : 0 ;
		$this->regFlat   = (isset($result->flat))     ? $result->flat     : 0 ;
		$this->regFias   = (isset($result->fiasCode)) ? $result->fiasCode : 0 ;
	}
	/**
	* Returns a partial user dataset
	* 
	* @param $result object
	* @return resource
	*/
	private function setPLVDataset($result) {
		$this->plvRegion = (isset($result->region))   ? $result->region   : 0 ;
		$this->plvCity   = (isset($result->city))     ? $result->city     : 0 ;
		$this->plvStreet = (isset($result->street))   ? $result->street   : 0 ;
		$this->plvHouse  = (isset($result->house))    ? $result->house    : 0 ;
		$this->plvFrame  = (isset($result->frame))    ? $result->frame    : 0 ;
		$this->plvFlat   = (isset($result->flat))     ? $result->flat     : 0 ;
		$this->plvFias   = (isset($result->fiasCode)) ? $result->fiasCode : 0 ;
	}

	/**
	* Returns a collection of user Data 
	* and performs some operations with an output userdata object
	* 
	* @param $result object
	* @return resource
	*/
	private function getUserDocCollection($url, $token) {
		$result  = json_decode(file_get_contents($url, false, $this->getRequestContext($token)));
		if ( !$result ) {
			$this->logmodel->addToLog("Unable to retrieve collection specified by document: ".$url."\n");
			return false;
		}
		if ($result->type === "PRG") {
			$this->setPRGDataset($result);
		}
		if ($result->type === "PLV") {
			$this->setPLVDataset($result);
		}
		if ($result->type === "EML") {
			$this->email   = (isset($result->value)) ? $result->value." ".$result->vrfStu : 0;
		}
		if ($result->type === "MBT") {
			$this->cellPhone  = (isset($result->value)) ? $result->value." ".$result->vrfStu : 0;
		}
	}

	private function checkForTokenAndOID ($token) {
		if ( !strlen($token) ) {
			$this->logmodel->addToLog("Access token is missing. Aborting\n");
			return false;
		}
		if ( !strlen($this->oid) ) {
			$this->logmodel->addToLog("Object ID is missing. Aborting\n");
			return false;
		}
		return true;
	}

	private function requestUserDocs($docList, $token) {
		if ( !$this->checkForTokenAndOID($token) ) {
			return false;
		}
		$this->logmodel->addToLog("\n------------------#-#-#------------------\nRequesting User Docs\n");
		foreach ($docList as $url) {
			$this->getUserDocCollection($url, $token);
		}
	}

	private function checkRegion($userdata, $pattern) {
		if ( $pattern->region === $userdata['prg']["region"] || $userdata['plv']["region"] ) {
			return 1;
		}
		return 0;
	}

	private function checkCity($userdata, $pattern) {
		$valid = 0;
		foreach ( $pattern->city as $city => $streets ) {
			if ( $city !== $userdata['prg']['city'] &&
				 $city !== $userdata['plv']['city'] &&
				 !stristr(str_replace(".", "", $userdata['birthplace']), $city)
			) {
				$valid = ($valid) ? 0 : 1;
			}
		}
		return $valid;
	}

	private function checkStreet($userdata, $pattern) {
		foreach ( $pattern->city as $streets ) {
			// если список улиц пустой, то подходит любая улица / город целиком 
			if ( !sizeof($streets) ) { return 1; }

			foreach ($streets as $street => $houses) {
				if ( sizeof($streets) && $street === $userdata['prg']["street"] || $street === $userdata['plv']["street"] ) {
					// если список домов пустой, то подходит любая дом / улица целиком 
					if ( !sizeof($houses) ) { return 1; }

					// если дом входит в список домов на улице 
					if ( is_array($houses) && sizeof($houses) && ( in_array( $userdata['prg']["house"], $houses) || in_array($userdata['plv']["house"], $houses ) )) {
						return 1;
					}
					return 0;
				}
			}
		}
	}

	public function processUserMatching($userdata, $objectID, $profile) {
		if ( $profile !== "address" ) {
			return 1;
		}
		$pattern = json_decode(file_get_contents($this->config->item("base_server_path")."tickets/".$objectID));
		$pattern = $pattern->matchParams;
		$valid = 1;
		if ( !isset($pattern->region) ) {
			return 1;
		}
		if ( isset($pattern->region) ) {
			$valid = $this->checkRegion($userdata, $pattern);
		}
		if ( $valid && isset($pattern->city) ) {
			$valid = $this->checkCity($userdata, $pattern);
		}
		if ( $valid && isset($pattern->city) && is_object($pattern->city) ) {
			$valid = $this->checkStreet($userdata, $pattern);
		}
		return $valid;
	}
}