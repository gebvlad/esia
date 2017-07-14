<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Userdatamodel extends CI_Model {

	function __construct() {
		parent::__construct();
	}

	/*  URL Retrieve  */

	/**
	* Returns an URL
	* @param string $URLType: code|token|user|address|contacts
	* @return string
	*/

	public function getURL($URLType='name') {
		$URLS = array(
			'code'       => 'aas/oauth2/ac?',
			'token'      => 'aas/oauth2/te',
			'name'       => 'rs/prns/'.$this->oid,
			'birthplace' => 'rs/prns/'.$this->oid,
			'address'    => 'rs/prns/'.$this->oid.'/addrs',
			'contacts'   => 'rs/prns/'.$this->oid.'/ctts'
		);
		return $this->portalUrl.$URLS[$URLType];
	}

	public $fullname       = null;
	public $reg_region     = null;
	public $reg_city       = null;
	public $reg_street     = null;
	public $reg_house      = null;
	public $reg_frame      = null;
	public $reg_flat       = null;
	public $reg_fias       = null;
	public $plv_region     = null;
	public $plv_city       = null;
	public $plv_street     = null;
	public $plv_house      = null;
	public $plv_frame      = null;
	public $plv_flat       = null;
	public $plv_fias       = null;
	public $birthplace     = null;
	public $email          = null;
	public $cel_ph         = null;
	public $trusted        = null;

	private $reqmode = null;

	/* DATA GETTERS */

	/**
	* Returns User Data object contents
	* 
	* @param $token string
	* @return string|false
	*/
	public function requestUserData($token="", $mode = 'name') {
		if ( !strlen($token) ) {
			$this->logmodel->addToLog("Access token is missing. Aborting\n");
			return false;
		}
		if ( !strlen($this->oid) ) {
			$this->logmodel->addToLog("Object ID is missing. Aborting\n");
			return false;
		}
		$this->logmodel->addToLog("\n------------------#-#-#------------------\nRequesting User Data\n");

		$url = $this->getURL($mode);
		$result  = json_decode(file_get_contents($url, false, $this->getRequestContext($token)));
		//print nl2br(str_replace(" ", "&nbsp;", print_r($result, true)));

		$this->logmodel->addToLog("\nUSER DATA REQUEST SUCCESS\n".print_r($result, true));
		
		if ($mode === 'birthplace') {
			$this->birthplace = $result->birthPlace;
		}

		if ($mode === 'name') {
			$this->fullname = implode( array($result->lastName, $result->firstName, $result->middleName), " " );
		}

		if ( isset( $result->trusted ) ) {
			$this->trusted = ($result->trusted) ? 1 : 0;
		}

		if ( isset( $result->elements ) ) {
			$this->requestUserDocs($result->elements, $token);
		}
	}

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

	private function getUserDocCollection($url, $token) {
		$result  = json_decode(file_get_contents($url, false, $this->getRequestContext($token)));
		//print nl2br(str_replace(" ", "&nbsp;", print_r($result, true)));
		if ($result->type === "PRG") {
			$this->reg_region = (isset($result->region))   ? $result->region   : 0 ;
			$this->reg_city   = (isset($result->city))     ? $result->city     : 0 ;
			$this->reg_street = (isset($result->street))   ? $result->street   : 0 ;
			$this->reg_house  = (isset($result->house))    ? $result->house    : 0 ;
			$this->reg_frame  = (isset($result->frame))    ? $result->frame    : 0 ;
			$this->reg_flat   = (isset($result->flat))     ? $result->flat     : 0 ;
			$this->reg_fias   = (isset($result->fiasCode)) ? $result->fiasCode : 0 ;
		}
		if ($result->type === "PLV") {
			$this->plv_region = (isset($result->region))   ? $result->region   : 0 ;
			$this->plv_city   = (isset($result->city))     ? $result->city     : 0 ;
			$this->plv_street = (isset($result->street))   ? $result->street   : 0 ;
			$this->plv_house  = (isset($result->house))    ? $result->house    : 0 ;
			$this->plv_frame  = (isset($result->frame))    ? $result->frame    : 0 ;
			$this->plv_flat   = (isset($result->flat))     ? $result->flat     : 0 ;
			$this->plv_fias   = (isset($result->fiasCode)) ? $result->fiasCode : 0 ;
		}
		if ($result->type === "EML") {
			$this->email   = (isset($result->value))       ? $result->value." ".$result->vrfStu     : 0 ;
		}
		if ($result->type === "MBT") {
			$this->cel_ph  = (isset($result->value))       ? $result->value." ".$result->vrfStu     : 0 ;
		}
	}

	private function requestUserDocs($docList, $token) {
		if ( !strlen($token) ) {
			$this->logmodel->addToLog("Access token is missing. Aborting\n");
			return false;
		}
		if ( !strlen($this->oid) ) {
			$this->logmodel->addToLog("Object ID is missing. Aborting\n");
			return false;
		}
		$this->logmodel->addToLog("\n------------------#-#-#------------------\nRequesting User Docs\n");
		$output = array();
		foreach ($docList as $url) {
			$this->getUserDocCollection($url, $token);
		}
		//print nl2br(str_replace(" ", "&nbsp;", print_r($output, true)));
		$this->logmodel->addToLog(print_r($output, true));
		return $output;
	}

	private function checkRegion($userdata, $pattern) {
		if ( $pattern->region === $userdata['prg']["region"] || $userdata['plv']["region"] ) {
			return 1;
		}
		return 0;
	}

	private function checkCity($userdata, $pattern) {

		//print_r($pattern->city);
		$valid = 0;
		foreach ( $pattern->city as $city => $streets ) {
			//print str_replace(".", "", $userdata['birthplace'])." - - ".$city;
			if ( $city !== $userdata['prg']['city'] &&
				 $city !== $userdata['plv']['city'] &&
				 !stristr(str_replace(".", "", $userdata['birthplace']), $city)
			) {
				$valid = ($valid) ? 1 : 0;
			} else {
				$valid = 0;
			}
		}
		return $valid;
	}

	private function checkStreet($userdata, $pattern) {
		foreach ( $pattern->city as $city => $streets ) {
			// если список улиц пустой, то подходит любая улица / город целиком
			if ( !sizeof($streets) ) {
				return 1;
			}
			foreach ($streets as $street => $houses) {
				if ( sizeof($streets) && $street === $userdata['prg']["street"] || $street === $userdata['plv']["street"] ) {
					$valid = 1;
					// если список домов пустой, то подходит любая дом / улица целиком
					if ( !sizeof($houses) ){
						return 1;
					}
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
		//print_r($userdata);
		//print nl2br(str_replace(" ", "&nbsp;", print_r($pattern, true)));
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