<?php
/**
 * Custom exception for passwordless. Contains an error code as a string in
 * the variable pwLessAuthErrorCode, accessible through the property
 * getPwLessAuthErrorCode. Do not use the Int variable getErrorCode().
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth;
require_once (__DIR__.'/Config/Config.php');

class PasswordLessAuthException extends \Exception {
	private $pwLessAuthErrorCode = PWLESS_ERROR_CODE_UNDEFINED_ERROR;

	// Redefine the exception so message isn't optional
    public function __construct($message, $pwLessAuthErrorCode = PWLESS_ERROR_CODE_UNDEFINED_ERROR, $errorCode = 0, $previous = null) {
		// assign the PasswordLessAuth error code and detail message
		$this->pwLessAuthErrorCode = $pwLessAuthErrorCode;

        // make sure everything is assigned properly
        parent::__construct($message, $errorCode, $previous);
    }

    // custom string representation of object
    public function __toString() {
        return __CLASS__ . ": [{$this->pwLessAuthErrorCode}]: {$this->message}\n";
    }

	// This method returns an array/JSON representation of the error, ready to be sent through the backend response.
	public function toErrorJsonResponse() {
        $data = array();
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = $this->pwLessAuthErrorCode;
        $data[PWLESS_API_PARAM_MESSAGE] = $this->message;
        return $data;
	}

	// custom password less auth error code
	public function getPwLessAuthErrorCode() {
		return $this->pwLessAuthErrorCode;
	}
}

?>
