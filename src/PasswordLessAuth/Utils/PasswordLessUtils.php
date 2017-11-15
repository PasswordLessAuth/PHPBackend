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
        $apiPrefix = "/api/"
        if (strncmp($requestUri, $apiPrefix, strlen($apiPrefix)) === 0) {
            $pageURL .= "/api";
        }
        return $pageURL;
    }

}

?>