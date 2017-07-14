<?php
defined('BASEPATH') OR exit('No direct script access allowed');

class Logmodel extends CI_Model {
	function __construct() {
		parent::__construct();
	}

	/* Logging */

	/**
	* Forms a logFile string depending on log mode
	* 
	* @param $logFile none|logfile|screen|both
	* @return string
	*/
	public function addToLog($message) {
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
	public function writeLog($logFile="") {
		$file = $this->config->item("base_server_path")."esia_log.log";
		if ( strlen($logFile) ) {
			$file = $this->config->item("base_server_path").$logFile;
		}
		$open = fopen($file, "w");
		fputs($open, $this->tlog);
		fclose($open);
	}

}