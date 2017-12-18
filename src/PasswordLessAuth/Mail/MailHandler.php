<?php

/**
 * This class performs all email sending operations for PasswordLessAuth.
 * The parameters and settings for the emails sent can be configured.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Mail;

require_once (__DIR__.'/../Config/Config.php');

use PasswordLessAuth\Mail\MailConfiguration;

class MailHandler {
    // variables/config
    private $mailConfig = null;
    
    public function __construct($configuration) {
        $this->mailConfig = ($configuration != null ? $configuration : new MailConfiguration());
    }
    
    public function updateConfiguration($configuration) {
        $this->mailConfig = ($configuration != null ? $configuration : new MailConfiguration());
    }
    
	/**
	 * Builds and send a registration security code that allows the user to perform privileged operations.
	 */
	public function sendSecurityCodeEmail($email, $security_code) {
        $htmlContent = file_get_contents($this->mailConfig->getSecurityCodeEmailPath());
        $serverContactName = $this->mailConfig->getContactEmail;
        $applicationName = $this->mailConfig->getServiceName();
        
        if ($htmlContent !== false) {
            $subject = "Your Security Code for ".$applicationName;
            $headers = "From: ".$serverContactName."\r\n";
            $headers .= "Reply-To: ".$serverContactName."\r\n";
            $headers .= "MIME-Version: 1.0\r\n";
            $headers .= "Content-Type: text/html; charset=UTF-8\r\n";

            $htmlContent = str_replace("{service}", $applicationName, $htmlContent);
            $htmlContent = str_replace("{code}", $security_code, $htmlContent);
            return mail($email, $subject, $htmlContent, $headers);
        }
		return false;
	}
        
	/**
	 * Builds and send the account confirmation email with the link to activate the user account.
     * This only makes sense if the account confirmation has been enabled for PasswordLessAuth.
	 */
	public function sendAccountConfirmationEmail($email) {
        $htmlContent = file_get_contents($this->mailConfig->getConfirmAccountEmailPath());
        $serverContactName = $this->mailConfig->getContactEmail;
        $applicationName = $this->mailConfig->getServiceName();
        
        if ($htmlContent !== false) {
            $subject = "Confirm your ".$applicationName." account.";
            $headers = "From: ".$serverContactName."\r\n";
            $headers .= "Reply-To: ".$serverContactName."\r\n";
            $headers .= "MIME-Version: 1.0\r\n";
            $headers .= "Content-Type: text/html; charset=UTF-8\r\n";

            $url = $this->mailConfig->getAPIURL() . PWLESS_ENDPOINT_CONFIRM_ACCOUNT;
            
            $htmlContent = str_replace("{service}", $applicationName, $htmlContent);
            $htmlContent = str_replace("{code}", $security_code, $htmlContent);
            $htmlContent = str_replace("{url}", $url, $htmlContent);
            return mail($email, $subject, $htmlContent, $headers);
        }
		return false;
	}
    
}

?>
