<?php

/**
 * This class contains general-purpose functions and utilities to be used
 * by the rest of classes of PasswordLessAuth.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Utils;

require_once (__DIR__.'/../Config/Config.php');

class PasswordLessUtils {

    /**
     * Tries to infer the Base URL for the API of the backend for this service, application or SaaS.
     */
    public static function getBaseAPIURL() {
        // http/https
        $pageURL = 'http';
        if (isset($_SERVER["HTTPS"]) && $_SERVER["HTTPS"] == "on") {$pageURL .= "s";}
        $pageURL .= "://";

        // base URL
        if (isset($_SERVER["SERVER_PORT"]) && $_SERVER["SERVER_PORT"] != "80") {
            $pageURL .= $_SERVER["SERVER_NAME"].":".$_SERVER["SERVER_PORT"];
        } else {
            $pageURL .= $_SERVER["SERVER_NAME"];
        }

        // /api ?
        $requestUri = $_SERVER["REQUEST_URI"];
        $apiPrefix = "/api/";
        if (strncmp($requestUri, $apiPrefix, strlen($apiPrefix)) === 0) {
            $pageURL .= "/api";
        }
        return $pageURL;
    }

    /**
     * Validating email address
     */
    public static function validateEmail($email) {
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $data = array();
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_MALFORMED_EMAIL_ADDRESS;
            $data[PWLESS_API_PARAM_MESSAGE] = "Email address is not valid";
            return false;
        }
        return true;
    }

	/**
	 * Returns a random english word from a dictionary of most common english words.
	 */
	public static function randomEnglishWord() {
        $lines = file(PWLESS_MOST_COMMON_ENGLISH_WORDS_FILE);
        $word = $lines[array_rand($lines)];
        $word = trim(preg_replace('/\s+/', ' ', $word));
		return word;
	}

}

?>
