<?php

/**
 * This class represents the mail configuration options for PasswordLessAuth.
 * The parameters and settings for the emails sent can be configured.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Mail;

use PasswordLessAuth\Utils\PasswordLessUtils;

require_once (__DIR__.'/../Config/Config.php');

class MailConfiguration {
    private $serviceName = null;                // Name or URL of this service, to be included in the emails.
    private $contactEmail = null;               // "From" email address, either a contact email address or a noreply one.
    private $customAPIURL = null;               // Custom URL for the API (optional).
    private $securityCodeEmailPath = null;      // Path for a custom email HTML/text code containing the security code email (optional).
    private $confirmAccountEmailPath = null;    // Path for a custom email HTML/text code containing the confirm account email (optional).
    
    // Initialization/setting variables
    
    public function __construct($serviceName = null, $contactEmail = null, $customAPIURL = null, $securityCodeEmailPath = null, $confirmAccountEmailPath = null) {
        $this->serviceName = $serviceName;
        $this->contactEmail = $contactEmail;
        $this->customAPIURL = $customAPIURL;
        $this->securityCodeEmailPath = $securityCodeEmailPath;
        $this->confirmAccountEmailPath = $confirmAccountEmailPath;
    }
    
    public function updateServiceNameAndContactEmail($serviceName, $contactEmail) {
        $this->serviceName = $serviceName;
        $this->contactEmail = $contactEmail;
    }

    public function setCustomAPIURL($customAPIURL) {
        $this->customAPIURL = $customAPIURL;
    }
    
    public function setSecurityCodeEmailPath($securityCodeEmailPath) {
        $this->securityCodeEmailPath = $securityCodeEmailPath;
    }
    
    public function setConfirmAccountEmailPath($confirmAccountEmailPath) {
        $this->confirmAccountEmailPath = $confirmAccountEmailPath;
    }
    
    // Mail configuration valid for account confirmation?
    
    public function mailConfigurationValidForAccountConfirmation() {
        if ($this->serviceName !== null && $this->contactEmail !== null) { return true; }
        else { return false; }
    }
    
    // Retrieving variables
    
    public function getServiceName() {
        if ($this->serviceName) { return $this->serviceName; }
        else { return $_SERVER['SERVER_NAME']; } // fallback
    }
    
    public function getContactEmail() {
        if ($this->contactEmail) { return $this->replyEmail; }
        else { return $_SERVER['SERVER_ADMIN']; } // fallback
    }
    
    public function getAPIURL() {
        if ($this->customAPIURL) { return $this->customAPIURL; }
        else { // try our best to guess the backend's API URL.
            return PasswordLessUtils::getBaseAPIURL();
        }
    }
    
    public function getSecurityCodeEmailPath() {
        if (isset($this->$customSecurityCodeEmailPath)) { return $this->$customSecurityCodeEmailPath; }
        else { return __DIR__."/../../resources/".PWLESS_SECURITY_CODE_FILENAME; }
    }
    
    public function getConfirmAccountEmailPath() {
        if (isset($this->$customSecurityCodeEmailPath)) { return $this->$confirmAccountEmailPath; }
        else { return __DIR__."/../../resources/".PWLESS_CONFIRM_ACCOUNT_FILENAME; }
    }
    
}

?>
