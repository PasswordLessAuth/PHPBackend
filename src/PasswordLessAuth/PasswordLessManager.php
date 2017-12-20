<?php
/**
 * This is the main manager for PasswordLessAuth.
 * Third party apps should interact with PasswordLessAuth mainly
 * through this class.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth;

require_once (__DIR__."/Config/Config.php");

// User id from db - Global Variable
$pwlessauth_user_id = null;
$pwlessauth_user_key = null;
$pwlessauth_user_info = null;

use \PasswordLessAuth\Database\DbHandler;
use \PasswordLessAuth\Encryption\EncryptionConfiguration;
use \PasswordLessAuth\Encryption\EncryptionHandler;
use \PasswordLessAuth\Encryption\ServerEncryptionEnvironment;
use \PasswordLessAuth\Mail\MailHandler;
use \PasswordLessAuth\Mail\MailConfiguration;
use \PasswordLessAuth\Utils\PasswordLessUtils;
use \PasswordLessAuth\PasswordLessAuthException;

class PasswordLessManager {
	// constants
	const PWLESS_FLOW_SIGNUP = "signup";
	const PWLESS_FLOW_LOGIN = "login";
	const PWLESS_FLOW_LOGOUT = "logout";
	const PWLESS_FLOW_CONFIRM = "confirm";
	const PWLESS_FLOW_ACCESS_TOKEN = "access_token";
	const PWLESS_FLOW_ADD_DEVICE = "add_device";
	const PWLESS_FLOW_DEL_DEVICE = "del_device";
	const PWLESS_FLOW_DEL_USER = "del_user";
	const PWLESS_FLOW_PWLESSINFO = "pwless_info";
	const PWLESS_FLOW_MYINFO = "my_info";
	const PWLESS_FLOW_GET_SETTINGS = "get_settings";
	const PWLESS_FLOW_GET_SETTING = "get_setting";
	const PWLESS_FLOW_SET_SETTING = "set_setting";
	const PWLESS_FLOW_DEL_SETTING = "del_setting";

    /** 
     * Settings:
     * - PWLESS_SETTING_CONFIRM_ACCOUNT_MODE: require email confirmation after registration? "none"=no, "lax"=yes, but allow 1 week of use, "strict"=yes, immediately
     * - PWLESS_SETTING_USE_SECURITY_NONCE: true/false
     * - PWLESS_SETTING_AUTHENTICATION_MODE: "strict"/"lax"
     * - PWLESS_SETTING_ACCEPTED_KEYS: list of keys accepted by the user, including types, lengths, digest algorithms, etc...
     */
    private $settings = array();
    
    // Slim application
    private $routeApp;
    
    // Database Handler. Must be a class implementing DbHandler.
    private $dbHandler;
    
    // Mail Handler.
    private $mailHandler;
    
    // Encryption public/private data for the server and encryption classes.
    private $serverEncryptionEnvironment = null;
    
	// hooks
	private $hooks = array();
	private $validFlowsToHook = [
		self::PWLESS_FLOW_SIGNUP,
		self::PWLESS_FLOW_LOGIN,
		self::PWLESS_FLOW_LOGOUT,
		self::PWLESS_FLOW_CONFIRM,
		self::PWLESS_FLOW_ACCESS_TOKEN,
		self::PWLESS_FLOW_ADD_DEVICE,
		self::PWLESS_FLOW_DEL_DEVICE,
		self::PWLESS_FLOW_DEL_USER,
		self::PWLESS_FLOW_PWLESSINFO,
		self::PWLESS_FLOW_MYINFO,
		self::PWLESS_FLOW_GET_SETTINGS,
		self::PWLESS_FLOW_GET_SETTING,
		self::PWLESS_FLOW_SET_SETTING,
		self::PWLESS_FLOW_DEL_SETTING
	];

    /**
     * ------------------ INITIALIZATION AND CONFIGURATION ------------------------
     */

    public function __construct($routeApp, $dbHandler, $serverEncryptionEnvironment, $options = array()) {
        if (! ($dbHandler instanceof DbHandler) ) { die("Invalid DbHandler for PasswordLessManager."); }
        if (! ($serverEncryptionEnvironment instanceof ServerEncryptionEnvironment) ) { die("Invalid ServerEncryptionEnvironment for PasswordLessManager."); }
        
        if ($dbHandler instanceof DbHandler) {
            // initialize dbHandler
            $this->dbHandler = $dbHandler;
            
            // initialize route app (Slim)
            $this->routeApp = $routeApp;
            
            // initialize mail handler
            $this->mailHandler = new MailHandler(null);
            $this->dbHandler->setMailHandler($this->mailHandler);
            
            // initialize encryption configurations for public/private server operations
            $this->serverEncryptionEnvironment = $serverEncryptionEnvironment;
            
            // Initialize database, overwriting previous one if specified.
            $this->dbHandler->initializePasswordLessAuthDatabase($this->optionValueForKey($options, PWLESS_OPTION_RECREATE_PWLESS_DATABASE));
            
            $this->initializeRoutes();
            $this->initializeSettings();
        } else { die("Invalid DbHandler for PasswordLessManager."); }
    }

    function initializeRoutes() {
		// authentication
        $this->routeApp->post('/pwless/signup', [$this, 'signup']);
        $this->routeApp->post('/pwless/login', [$this, 'login']);
        $this->routeApp->post('/pwless/confirm', [$this, 'confirm']);
        $this->routeApp->post('/pwless/access', [$this, 'accessToken']);
        $this->routeApp->post('/pwless/logout', [$this, 'logout'])->add([$this, 'authenticate']);

		// devices
        $this->routeApp->post('/pwless/devices', [$this, 'addDevice']);
        $this->routeApp->delete('/pwless/devices', [$this, 'deleteDevice']);
        $this->routeApp->delete('/pwless/me', [$this, 'deleteUserAccount'])->add([$this, 'authenticate']);

		// info
        $this->routeApp->get('/pwless/info', [$this, 'pwLessInfo']);
        $this->routeApp->get('/pwless/me', [$this, 'myInfo'])->add([$this, 'authenticate']);

		// settings
        $this->routeApp->get('/pwless/settings', [$this, 'getUserSettings'])->add([$this, 'authenticate']);
        $this->routeApp->get('/pwless/settings/{setting}', [$this, 'getUserSetting'])->add([$this, 'authenticate']);
        $this->routeApp->put('/pwless/settings/{setting}', [$this, 'setUserSetting'])->add([$this, 'authenticate']);
        $this->routeApp->delete('/pwless/settings/{setting}', [$this, 'deleteUserSetting'])->add([$this, 'authenticate']);
    }
    
    function optionValueForKey($options, $key) {
        if (is_array($options) && array_key_exists($key, $options)) {
            return $options[$key];
        } else {
            return null;
        }
    }
    
    public function resetPasswordLessAuthDatabase() {
        $this->dbHandler->initializePasswordLessAuthDatabase(true);
    }
    
	public function addCustomRoute($route, $httpVerb, $func, $requiresAuthentication = true, $prependPwLessPath = false) {
		$finalPath = $prependPwLessPath ? "/pwless" . $route : $route;
		$route = null;

		switch (mb_strtolower($httpVerb)) {
			case "get":
				$this->routeApp->get($finalPath, $func);
				break;
			case "post":
				$this->routeApp->post($finalPath, $func);
				break;
			case "delete":
				$this->routeApp->delete($finalPath, $func);
				break;
			case "put":
				$this->routeApp->put($finalPath, $func);
				break;
			default:
				break;
		}
		if ($route !== null && $requiresAuthentication) {
			$route->add([$this, 'authenticate']);
		}
	}

    /**
     * --------------------------------- HOOKS ---------------------------------
     */
    /**
	 * This function allows you to define custom hooks that will be executed right after a flow has been
	 * executed. Thus, there's a hook after the signup floor, a hookup after the login flow, etc...
	 * The hook will be called with two parameters: $success and $data.
	 * The first one will indicate the success or failure status of the executed flow.
	 * The second one will contain data relative to the flow if it was successfully executed.
	 * The data returned in each flow is:
	 * - PWLESS_FLOW_SIGNUP: the newly created user object.
	 * - PWLESS_FLOW_LOGIN': the login token for the user.
	 * - PWLESS_FLOW_ACCESS_TOKEN: the access token info for the user.
	 * - PWLESS_FLOW_ADD_DEVICE: the updated user object containing the newly added device.
	 * - PWLESS_FLOW_DEL_DEVICE: no data is returned by this flow.
	 * - PWLESS_FLOW_PWLESSINFO: the info to be returned to the user.
	 * - PWLESS_FLOW_MYINFO: the user information.
	 * - PWLESS_FLOW_GET_SETTINGS: the settings to be returned to the user.
	 * - PWLESS_FLOW_GET_SETTING: the setting to be returned to the user.
	 * - PWLESS_FLOW_SET_SETTING: set newly created or updated setting.
	 * - PWLESS_FLOW_DEL_SETTING: returns no data.
 	 * @param String flow	A PasswordLessAuth flow, one of PWLESS_FLOW_*
	 * @param Callable hook	The callable (function or class method) to hook to the flow.
	 * @returns true if the hook was properly created for the flow. False if the hook or flow were invalid.
     */
	public function setHookForFlow($flow, $hook) {
		if (!is_callable($hook)) { throw new \Exception("Invalid hook, must be a callable function."); }
		if (!in_array($flow, $this->validFlowsToHook)) { throw new \Exception("Invalid flow, must be one of PaswordLessAuth flows."); }

		$this->hooks[$flow] = $hook;
		return true;
	}

	/**
	 * Deletes a hook for a flow. Look at setHookForFlow for an explanation of the $flow variable.
	 * @param String flow	A PasswordLessAuth flow, one of PWLESS_FLOW_* (see setHookForFlow)
	 */
	function delHookForFlow($flow) {
		unset($this->hooks[$flow]);
	}

    /**
     * --------------------------------- ENCRYPTION ---------------------------------
     */
    
    function publicEncryptionHandler()  { return $this->serverEncryptionEnvironment->getPublicEncryptionHandler(); }
    function privateEncryptionHandler() { return $this->serverEncryptionEnvironment->getPrivateEncryptionHandler(); }

	/**
	 * Returns an encryption handler ready to perform operations with the public key of a concrete user.
	 */
	public function encryptionHandlerForAuthenticatedUser() {
		global $pwlessauth_user_id;
		global $pwlessauth_user_key;
		if (!$pwlessauth_user_id || !$pwlessauth_user_key) { return false; }
		else {
			$keyObject = $this->dbHandler->getFullKeyInformationForUserWithId($pwlessauth_user_id, $pwlessauth_user_key);
			if (!$keyObject) { return false; }
			else {
				$encConfig = new EncryptionConfiguration(
					$keyObject[PWLESS_API_PARAM_KEY_DATA],				// key data
					$keyObject[PWLESS_API_PARAM_KEY_TYPE], 				// key type
					$keyObject[PWLESS_API_PARAM_KEY_LENGTH], 			// key length
					$keyObject[PWLESS_API_PARAM_SIGNATURE_ALGORITHM], 	// signature algorithm for the key
					PWLESS_KEY_TYPE_PUBLIC 								// PUBLIC key
				);
				return new EncryptionHandler($encConfig);
			}
		}
	}

    /**
     * --------------------------------- SETTINGS ---------------------------------
     */
    
    /**
     * Sets the default settings for PasswordLessAuth. The settings can be modified by
     * calling setSetting(setting, value).
     */
    function initializeSettings() {
        $this->settings = array();
        $this->settings[PWLESS_SETTING_ACCEPTED_KEYS] = $this->keyInformationForServer();
        $this->settings[PWLESS_SETTING_USE_SECURITY_NONCE] = true;                               // use security nonce by default.
        $this->settings[PWLESS_SETTING_AUTHENTICATION_MODE] = PWLESS_AUTHENTICATION_MODE_STRICT; // strict mode by default.
        $this->settings[PWLESS_SETTING_CONFIRM_ACCOUNT_MODE] = PWLESS_CONFIRMATION_EMAIL_NONE;   // don't require email confirmation by default.
        $this->settings[PWLESS_SETTING_MAIL_CONFIGURATION] = new MailConfiguration();                // standard mail configuration.
    }
    
    /**
     * Returns the key information for the server, including the accepted key types, lengths, etc.
     */
    function keyInformationForServer() {
        $rsaLengths = array(2048, 4096);
        $ecLengths = array(256);
        $rsaAlgorithms = array('SHA1');
        $ecAlgorithms = array('ecdsa-with-SHA1');
        $rsa = array();
        $ec = array();
        $rsa[PWLESS_API_PARAM_KEY_LENGTH] = $rsaLengths;
        $ec[PWLESS_API_PARAM_KEY_LENGTH] = $ecLengths;
        $rsa[PWLESS_API_PARAM_SIGNATURE_ALGORITHM] = $rsaAlgorithms;
        $ec[PWLESS_API_PARAM_SIGNATURE_ALGORITHM] = $ecAlgorithms;
        $acceptedKeys = array();
        $acceptedKeys["rsa"] = $rsa;
        $acceptedKeys["ec"] = $ec;
        return $acceptedKeys;
    }
    
    /**
     * Sets a setting with a concrete value. If the setting is not part of the
     * PasswordLessAuth set of settings, it will be ignored.
     * @param String $setting Key for the setting to modify
     * @param Mixed $value    Value to set for the setting
     * @return Bool           true if the setting was modified, false otherwise
     */
    public function setSetting($setting, $value) {
        if (array_key_exists($setting, $this->settings)) {
			// confirm account mode can only be configured via "enableAccountEmailConfirmation".
			if ($setting == PWLESS_SETTING_CONFIRM_ACCOUNT_MODE) { return false; }

            $this->settings[$setting] = $value;
            return true;
        }
        return false;
    }
    
    /**
     * Gets an array with all the PUBLIC settings, ready to be sent to the client.
     */
    public function getAllSettings() {
        $settings = array();
        $settings[PWLESS_SETTING_ACCEPTED_KEYS] = $this->settings[PWLESS_SETTING_ACCEPTED_KEYS];
        $settings[PWLESS_SETTING_USE_SECURITY_NONCE] = $this->settings[PWLESS_SETTING_USE_SECURITY_NONCE];
        $settings[PWLESS_SETTING_AUTHENTICATION_MODE] = $this->settings[PWLESS_SETTING_AUTHENTICATION_MODE];
        $settings[PWLESS_SETTING_CONFIRM_ACCOUNT_MODE] = $this->settings[PWLESS_SETTING_CONFIRM_ACCOUNT_MODE];
        
        return $settings;
    }
    
    /**
     * Gets the value for a given setting, or null if the setting cannot be found.
     */
    public function getValueForSetting($setting) {
        if (array_key_exists($setting, $this->settings)) { return $this->settings[$setting]; }
        else { return null; }
    }
    
    /**
     * Enables email account confirmation. You must provide the service name or URL for your
     * application or SaaS, the reply email address and, optionally, a custom content for the
     * 
     */
    function enableAccountEmailConfirmation($emailConfirmationMode, $mailConfiguration) {
        if ($emailConfirmationMode === PWLESS_CONFIRMATION_EMAIL_LAX || $emailConfirmationMode === PWLESS_CONFIRMATION_EMAIL_STRICT) {
			if ($this->setPasswordLessMailConfiguration($mailConfiguration)) {
                $this->settings[PWLESS_SETTING_CONFIRM_ACCOUNT_MODE] = $emailConfirmationMode;
				return true;
			} else { return false; }
        } else {
            $this->settings[PWLESS_SETTING_CONFIRM_ACCOUNT_MODE] = PWLESS_CONFIRMATION_EMAIL_NONE;
            return $this->setPasswordLessMailConfiguration($mailConfiguration);
        }
    }
    
    /**
     * Returns true if account confirmation via email is enabled, either lax or strict.
     */
    function mustConfirmAccountByEmail() {
        $confirmMode = $this->getValueForSetting(PWLESS_SETTING_CONFIRM_ACCOUNT_MODE);
        if (!$confirmMode) { return false; }
        else if ($confirmMode == PWLESS_CONFIRMATION_EMAIL_LAX || $confirmMode == PWLESS_CONFIRMATION_EMAIL_STRICT) { return true; }
        return false;
    }
    
    /**
     * Updates the configuration for the mail handler and propagates it to the DbHandler
     */
    public function setPasswordLessMailConfiguration($mailConfiguration) {
		if ($mailConfiguration instanceof MailConfiguration && $mailConfiguration->mailConfigurationValidForAccountConfirmation()) {
			$this->settings[PWLESS_SETTING_MAIL_CONFIGURATION] = $mailConfiguration;
			$this->mailHandler->updateConfiguration($mailConfiguration);
			$this->dbHandler->setMailHandler($mailConfiguration);
			return true;
		} else {
			return false;
		}
    }
    
    /**
     * ------------------------------ AUTHENTICATION ------------------------------
     */

    /**
     * Adding Middle Layer to authenticate every request
     * Checking if the request has valid api key in the 'Authorization' header
     */
    public function authenticate ($req, $res, $next) {
        // Getting request headers
        $headersApache = apache_request_headers();
        $headers = $req->getHeaders();

        // Verifying Authorization Header
        $requestParams = $this->getParametersFromRequest($req);
        $authenticated = false;

        if (isset($requestParams['Authorization'])) {
            $accessToken = $requestParams['Authorization'];
            $authenticated = $this->authenticateWithAccessToken($accessToken);
        } else if (isset($headers['Authorization'])) {
            // get the access token
            $accessToken = $headers['Authorization'];
            $authenticated = $this->authenticateWithAccessToken($accessToken);
        } else if (isset($headersApache['Authorization'])) {
            // get the access token
            $accessToken = $headersApache['Authorization'];
            $authenticated = $this->authenticateWithAccessToken($accessToken);
        }

        if ($authenticated) {
            $res = $next($req, $res);
            return $res;
        } else {
            $data = array();
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_MESSAGE] = "Access Denied. Invalid or expired access token, or unconfirmed user account.";
            return $this->response($res, 401, $data);
        }
    }

    function authenticateWithAccessToken($accessToken) {
        // validating api key
        $userIdAndKey = $this->dbHandler->userIdAndDeviceKeyForAccessToken($accessToken);
        if ($userIdAndKey === false) {
            return false;
        } else {
            // get user primary key id
            global $pwlessauth_user_id;
            global $pwlessauth_user_key;
            $pwlessauth_user_id = $userIdAndKey[0];
			$pwlessauth_user_key = $userIdAndKey[1];
			// set user data
			global $pwlessauth_user_info;
			$pwlessauth_user_info = $this->dbHandler->getUserById($pwlessauth_user_id);

            return true;
        }
    }

	/**
     * Returns the authenticated user ID (if there's an authenticated user.)
	 * @return Int the integer containing the user ID.
	 */
	public function authenticatedUserId() {
		global $pwlessauth_user_id;
		return $pwlessauth_user_id;
	}

	/**
     * Returns the authenticated user Key ID (if there's an authenticated user.)
	 * @return Int the integer containing the user ID.
	 */
	public function authenticatedUserKeyId() {
		global $pwlessauth_user_key;
		return $pwlessauth_user_key;
	}

	/**
     * Returns the authenticated user data (if there's an authenticated user.)
	 * @param Object an associative array with the user's data, including id, email, etc...
	 */
	public function authenticatedUserData() {
		global $pwlessauth_user_info;
		return $pwlessauth_user_info;
	}


    /**
     * ------------------------------ REGISTRATION ------------------------------
     */

    /**
     * User Registration
     * url - /pwless/signup
     * method - POST
     * params - email, key_data, key_type, key_length, signature_algorithm
     */
    function signup ($req, $res, $args) {
        // check for required params
        $requestParams = $this->getParametersFromRequest($req);
        if ($missingParams = $this->missingParametersForRequest($res, $requestParams,
        array(PWLESS_API_PARAM_EMAIL, PWLESS_API_PARAM_KEY_DATA, PWLESS_API_PARAM_KEY_TYPE, PWLESS_API_PARAM_KEY_LENGTH, PWLESS_API_PARAM_SIGNATURE_ALGORITHM))) {
            $result = $this->missingParametersResponse($missingParams);
			$this->executeHook(self::PWLESS_FLOW_SIGNUP, false, "Missing parameters for request");
			return $this->response($res, 400, $result);
        }

        // mandatory params
        $email = $requestParams[PWLESS_API_PARAM_EMAIL];
        $publicKey = $requestParams[PWLESS_API_PARAM_KEY_DATA];
        $keyType = $requestParams[PWLESS_API_PARAM_KEY_TYPE];
        $keyLength = $requestParams[PWLESS_API_PARAM_KEY_LENGTH];
        $signatureAlgorithm = $requestParams[PWLESS_API_PARAM_SIGNATURE_ALGORITHM];
        
        // validating email address
        if (!PasswordLessUtils::validateEmail($email)) {
			$result = $this->badResponse(PWLESS_ERROR_CODE_MALFORMED_EMAIL_ADDRESS, "Email address is not valid");
			$this->executeHook(self::PWLESS_FLOW_SIGNUP, false, "Email address is not valid");
			return $this->response($res, 400, $result);
		}

        // optional parameters
        // if server security nonce is enabled and we receive a security nonce, sign it.
        $securityNonceSigned = $this->securityTokenSignedIfAvailable($requestParams);
        // device info?
        $deviceInfo = "Unknown device";
        if (isset($requestParams[PWLESS_API_PARAM_DEVICE_INFO])) { $deviceInfo = $requestParams[PWLESS_API_PARAM_DEVICE_INFO]; }

		// must confirm email?
		$mustConfirmEmail = $this->mustConfirmAccountByEmail();

		$httpCode = 200;
		$result = null;
		try {
        	$registeredUser = $this->dbHandler->registerUser($email, $publicKey, $keyType, $keyLength, $deviceInfo, $signatureAlgorithm, $securityNonceSigned, $mustConfirmEmail);
			$result = $this->userSuccessfullyRegisteredResponse($registeredUser, $securityNonceSigned);
			$this->executeHook(self::PWLESS_FLOW_SIGNUP, true, $registeredUser);
		} catch (PasswordLessAuthException $e) {
			$httpCode = 400;

			// user already exists?
			if ($e->getPwLessAuthErrorCode() == PWLESS_ERROR_CODE_USER_ALREADY_EXISTS) {
				$userSecurityCode = $this->dbHandler->securityCodeForUserWithEmail($email);
				if ($this->mailHandler->sendSecurityCodeEmail($email, $userSecurityCode)) {
					$result = $this->codeValidationRequiredResponse($securityNonceSigned);
					$this->executeHook(self::PWLESS_FLOW_SIGNUP, false, "User already exists. Code validation needed.");
				} else {
					$result = $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_SEND_MAIL, "Error sending security code email for device registration.");
					$this->executeHook(self::PWLESS_FLOW_SIGNUP, false, "Error sending security code email for device registration.");
				}
			} else {
				$result = $e->toErrorJsonResponse();
				$this->executeHook(self::PWLESS_FLOW_SIGNUP, false, $e);
			}
		}
        return $this->response($res, $httpCode, $result);
    }
    
    /**
     * Confirms user registration, if needed.
     * url - /pwless/confirm
     * method - POST
     * params - code
     */
    function confirm($req, $res, $args) {
        // check for required params
        $requestParams = $this->getParametersFromRequest($req);
        if ($missingParams = $this->missingParametersForRequest($res, $requestParams, array(PWLESS_API_PARAM_CODE))) {
            $result = $this->missingParametersResponse($missingParams);
			$this->executeHook(self::PWLESS_FLOW_CONFIRM, false, "Missing parameters for request");
			return $this->response($res, 400, $result);
        }

        // mandatory params
        $code = $requestParams[PWLESS_API_PARAM_CODE];

        // extract code and check validity
        $email = $this->publicEncryptionHandler()->decrypt_message($code);
        if ($email) {
			$result = $this->simpleSuccessfulResponse("Account successfully confirmed. Thank you.");
			$this->executeHook(self::PWLESS_FLOW_CONFIRM, true, $email);
			return $this->response($res, 200, $result);
		} else {
			$result = $this->badVerificationCodeResponse();
			$this->executeHook(self::PWLESS_FLOW_CONFIRM, false, "Invalid code for account confirmation.");
			return $this->response($res, 400, $result);
		}
    }

    /**
     * ------------------------------ LOGIN ------------------------------
     */

    /**
     * Starts the login flow, validating the user's request (user and device) and returning the login token.
     * url - /pwless/login
     * method - POST
     * params - email, key_id
     */
    function login ($req, $res, $args) {
        // check for required params
        $requestParams = $this->getParametersFromRequest($req);
        if ($missingParams = $this->missingParametersForRequest($res, $requestParams, array(PWLESS_API_PARAM_EMAIL, PWLESS_API_PARAM_KEY_ID))) {
            $result = $this->missingParametersResponse($missingParams);
			$this->executeHook(self::PWLESS_FLOW_LOGIN, false, "Missing parameters for request");
			return $this->response($res, 400, $result);
        }

        // mandatory params
        $email = $requestParams[PWLESS_API_PARAM_EMAIL];
        $keyId = $requestParams[PWLESS_API_PARAM_KEY_ID];
        // optional security nonce
        $securityNonceSigned = $this->securityTokenSignedIfAvailable($requestParams);

        // check user status
        if (!$this->dbHandler->userStatusIsValid($email, $this->getValueForSetting(PWLESS_SETTING_CONFIRM_ACCOUNT_MODE))) {
			$result = $this->accountInvalidResponse();
			$this->executeHook(self::PWLESS_FLOW_LOGIN, false, "Invalid user or unconfirmed account. Cannot login.");
			return $this->response($res, 401, $result);
		}

        // generate login request
        $result = $this->dbHandler->generateLoginRequest($email, $keyId);
        $data = array();
        if ($result === false) {
            // unknown user.
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_IDENTITY_VALIDATION_FAILED;
            $data[PWLESS_API_PARAM_MESSAGE] = "Login failed. Identity validation failed.";
			$this->executeHook(self::PWLESS_FLOW_LOGIN, false, $data[PWLESS_API_PARAM_MESSAGE]);
            return $this->response($res, 401, $data);
        } else {
            $data[PWLESS_API_PARAM_SUCCESS] = true;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
            $data[PWLESS_API_PARAM_LOGIN_TOKEN] = $result;
            if ($securityNonceSigned !== false) { $data[PWLESS_API_PARAM_SEC_NONCE_SIGNED] = $securityNonceSigned; }
			$this->executeHook(self::PWLESS_FLOW_LOGIN, true, $result);
            return $this->response($res, 200, $data);
        }
    }

    /**
     * Returns a valid access token by validating a user's login token signature request.
     * url - /pwless/access
     * method - POST
     * params - email, key_id, login_key_signed
     */
    function accessToken($req, $res, $args) {
        // verify required authentication_type
        $requestParams = $this->getParametersFromRequest($req);
        if ($missingParams = $this->missingParametersForRequest($res, $requestParams, array(PWLESS_API_PARAM_EMAIL, PWLESS_API_PARAM_KEY_ID, PWLESS_API_PARAM_LOGIN_TOKEN_SIGNED))) {
            $result = $this->missingParametersResponse($missingParams);
			$this->executeHook(self::PWLESS_FLOW_ACCESS_TOKEN, false, "Missing parameters for request");
			return $this->response($res, 400, $result);
        }

        $email = $requestParams[PWLESS_API_PARAM_EMAIL];
        $keyId = $requestParams[PWLESS_API_PARAM_KEY_ID];
        $loginTokenSigned = $requestParams[PWLESS_API_PARAM_LOGIN_TOKEN_SIGNED];

        // check user status
        if (!$this->dbHandler->userStatusIsValid($email, $this->getValueForSetting(PWLESS_SETTING_CONFIRM_ACCOUNT_MODE))) {
			$result = $this->accountInvalidResponse();
			$this->executeHook(self::PWLESS_FLOW_ACCESS_TOKEN, false, "Invalid user or unconfirmed account. Cannot get access token.");
			return $this->response($res, 401, $result);
		}

		$httpCode = 200;
		$result = null;
		try {
			$result = $this->dbHandler->validateLogin($email, $keyId, $loginTokenSigned, $this->getValueForSetting(PWLESS_SETTING_AUTHENTICATION_MODE));
			$result[PWLESS_API_PARAM_SUCCESS] = true;
			$result[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
			$result[PWLESS_API_PARAM_MESSAGE] = "Access granted.";
			$this->executeHook(self::PWLESS_FLOW_ACCESS_TOKEN, true, $result[PWLESS_API_PARAM_AUTH][PWLESS_API_PARAM_ACCESS_TOKEN]);
		} catch (PasswordLessAuthException $e) {
			$httpCode = 400;
			$result = $e->toErrorJsonResponse();
			$this->executeHook(self::PWLESS_FLOW_ACCESS_TOKEN, false, $e);
		}
        return $this->response($res, $httpCode, $result);
    }


    /**
     * Starts the logout flow, replacing the access token with another one that won't be valid for any user.
     * url - /pwless/logout
     * method - POST
     * params - none
     */
    function logout ($req, $res, $args) {
        global $pwlessauth_user_id;
		global $pwlessauth_user_key;

        // generate login request
        $result = $this->dbHandler->logoutUser($pwlessauth_user_id, $pwlessauth_user_key);
        $data = array();
        if ($result === false) {
            // unknown user.
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_UNDEFINED_ERROR;
            $data[PWLESS_API_PARAM_MESSAGE] = "You didn't think you could escape so easily, now did you?";
			$this->executeHook(self::PWLESS_FLOW_LOGOUT, false, $data[PWLESS_API_PARAM_MESSAGE]);
            return $this->response($res, 400, $data);
        } else {
            $data[PWLESS_API_PARAM_SUCCESS] = true;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
            $data[PWLESS_API_PARAM_MESSAGE] = "You are successfully logged out. We miss you already!";
			$this->executeHook(self::PWLESS_FLOW_LOGOUT, true, array($pwlessauth_user_id, $pwlessauth_user_key));
            return $this->response($res, 200, $data);
        }
    }

    /*
     * -------------------- DEVICES AND KEY MANAGEMENT --------------------
     */

    /**
     * Adds a new device (and associated key) for a user.
     * method POST
     * url /pwless/devices
	 * params - email, key_data, key_type, key_length, signature_algorithm
     */
    function addDevice ($req, $res, $args) {
        // check for required params
        $requestParams = $this->getParametersFromRequest($req);
        if ($missingParams = $this->missingParametersForRequest($res, $requestParams,
        array(PWLESS_API_PARAM_EMAIL, PWLESS_API_PARAM_KEY_DATA, PWLESS_API_PARAM_KEY_TYPE, PWLESS_API_PARAM_KEY_LENGTH, PWLESS_API_PARAM_SIGNATURE_ALGORITHM))) {
            $result = $this->missingParametersResponse($missingParams);
			$this->executeHook(self::PWLESS_FLOW_ADD_DEVICE, false, "Missing parameters for request");
			return $this->response($res, 400, $result);
        }

        // mandatory params
        $email = $requestParams[PWLESS_API_PARAM_EMAIL];
        $publicKey = $requestParams[PWLESS_API_PARAM_KEY_DATA];
        $keyType = $requestParams[PWLESS_API_PARAM_KEY_TYPE];
        $keyLength = $requestParams[PWLESS_API_PARAM_KEY_LENGTH];
        $signatureAlgorithm = $requestParams[PWLESS_API_PARAM_SIGNATURE_ALGORITHM];

        // validating email address
        if (!PasswordLessUtils::validateEmail($email)) {
			$result = $this->badResponse(PWLESS_ERROR_CODE_MALFORMED_EMAIL_ADDRESS, "Email address is not valid");
			$this->executeHook(self::PWLESS_FLOW_ADD_DEVICE, false, "Email address is not valid");
			return $this->response($res, 400, $result);
		}

        // optional parameters
        // if server security nonce is enabled and we receive a security nonce, sign it.
        $securityNonceSigned = $this->securityTokenSignedIfAvailable($requestParams);
        // device info?
        $deviceInfo = "Unknown device";
        if (isset($requestParams[PWLESS_API_PARAM_DEVICE_INFO])) {
			$deviceInfo = $requestParams[PWLESS_API_PARAM_DEVICE_INFO];
		}
        // security code?
        $providedSecurityCode = false;
        if (isset($requestParams[PWLESS_API_PARAM_SECURITY_CODE])) {
			$providedSecurityCode = $requestParams[PWLESS_API_PARAM_SECURITY_CODE];
		}

		$httpCode = 200;
		try {
			$userAndKeyData = $this->dbHandler->addDeviceToUser($email, $publicKey, $keyType, $keyLength, $deviceInfo, $signatureAlgorithm, $providedSecurityCode);
			$result = $this->userSuccessfullyRegisteredResponse($userAndKeyData, $securityNonceSigned);
			$this->executeHook(self::PWLESS_FLOW_ADD_DEVICE, true, $userAndKeyData);
		} catch (PasswordLessAuthException $e) {
			$result = $e->toErrorJsonResponse();
			$httpCode = 400;
			$this->executeHook(self::PWLESS_FLOW_ADD_DEVICE, false, $e);
		}
        return $this->response($res, $httpCode, $result);
    }

    /**
     * Removes a device (and associated key) for a user.
     * method DELETE
     * url /pwless/devices
	 * params - email, key_id, security_code
     */
    function deleteDevice ($req, $res, $args) {
        // check for required params
        $requestParams = $this->getParametersFromRequest($req);
        if ($missingParams = $this->missingParametersForRequest($res, $requestParams,
        array(PWLESS_API_PARAM_EMAIL, PWLESS_API_PARAM_KEY_ID))) {
            $result = $this->missingParametersResponse($missingParams);
			$this->executeHook(self::PWLESS_FLOW_DEL_DEVICE, false, "Missing parameters for request");
			return $this->response($res, 400, $result);
        }

        // mandatory params
        $email = $requestParams[PWLESS_API_PARAM_EMAIL];
        $keyId = $requestParams[PWLESS_API_PARAM_KEY_ID];

        // do we have a security code?
        $providedSecurityCode = false;
        if (isset($requestParams[PWLESS_API_PARAM_SECURITY_CODE])) {
			$providedSecurityCode = $requestParams[PWLESS_API_PARAM_SECURITY_CODE];
			$httpCode = 200;
			$result = null;
			try {
				if ($this->dbHandler->deleteUserDeviceAndKeyEntry($email, $keyId, $providedSecurityCode)) {
					$result = $this->requestSucceededResponse();
					$this->executeHook(self::PWLESS_FLOW_DEL_DEVICE, true, "Device and associated key successfully deleted");
				} else {
					$httpCode = 400;
					$result = $this->badRequestResponse();
					$this->executeHook(self::PWLESS_FLOW_DEL_DEVICE, false, "An error happened while trying to delete the device and associated key.");
				}
			} catch (PasswordLessAuthException $e) {
				$result = $e->toErrorJsonResponse();
				$httpCode = 400;
				$this->executeHook(self::PWLESS_FLOW_DEL_DEVICE, false, $e);
			}
        	return $this->response($res, $httpCode, $result);
		} else { // require security code
			$httpCode = 400;
			$userSecurityCode = $this->db->securityCodeForUserWithEmail($email);
            if ($this->mailHandler->sendSecurityCodeEmail($email, $userSecurityCode)) {
				$this->executeHook(self::PWLESS_FLOW_DEL_DEVICE, false, "Code validation required for deleting device.");
                $result =  $this->codeValidationRequiredResponse(false);
            } else {
				$this->executeHook(self::PWLESS_FLOW_DEL_DEVICE, false, "Unable to delete device and key for user. Unable to send security confirmation code to the user.");
				$result = $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_SEND_MAIL, "Unable to delete device and key for user. Unable to send security confirmation code to the user.");
			}
        	return $this->response($res, $httpCode, $result);
		}

    }

    /**
     * Removes the user account, including all their settings, devices/keys and the user data.
	 * Requires confirmation through security code.
     * method DELETE
     * url /pwless/me
	 * params - security_code
     */
    function deleteUserAccount ($req, $res, $args) {
		global $pwlessauth_user_id;
		global $pwlessauth_user_key;

        // do we have a security code?
        $providedSecurityCode = false;
        if (isset($requestParams[PWLESS_API_PARAM_SECURITY_CODE])) {
			$providedSecurityCode = $requestParams[PWLESS_API_PARAM_SECURITY_CODE];
			$httpCode = 200;
			$result = null;
			try {
				if ($this->dbHandler->deleteUserDeviceAndKeyEntry($email, $pwlessauth_user_key, $providedSecurityCode)) {
					$result = $this->requestSucceededResponse();
					$this->executeHook(self::PWLESS_FLOW_DEL_USER, true, "Device and associated key successfully deleted");
				} else {
					$httpCode = 400;
					$result = $this->badRequestResponse();
					$this->executeHook(self::PWLESS_FLOW_DEL_USER, false, "An error happened while trying to delete the device and associated key.");
				}
			} catch (PasswordLessAuthException $e) {
				$result = $e->toErrorJsonResponse();
				$httpCode = 400;
				$this->executeHook(self::PWLESS_FLOW_DEL_USER, false, $e);
			}
        	return $this->response($res, $httpCode, $result);
		} else { // require security code
			$httpCode = 400;
			$userSecurityCode = $this->db->securityCodeForUserWithEmail($email);
            if ($this->mailHandler->sendSecurityCodeEmail($email, $userSecurityCode)) {
				$this->executeHook(self::PWLESS_FLOW_DEL_USER, false, "Code validation required for deleting user account.");
                $result =  $this->codeValidationRequiredResponse(false);
            } else {
				$this->executeHook(self::PWLESS_FLOW_DEL_USER, false, "Unable to delete user account. Error sending security confirmation code to the user.");
				$result = $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_SEND_MAIL, "Unable to delete user account. Error sending security confirmation code to the user.");
			}
        	return $this->response($res, $httpCode, $result);
		}

    }

    /*
     * --------------------- INFORMATION METHODS ----------------------
     */

    /**
     * Returns the information about the requesting user, including devices and keys.
     * method GET
     * url /pwless/me
	 * params - none
     */
    function pwLessInfo ($req, $res, $args) {
        $data = array();

        // settings
        $data[PWLESS_API_PARAM_SETTINGS] = $this->getAllSettings();

        // public key info
        $data[PWLESS_API_PARAM_PUBLIC_KEY] = $this->publicEncryptionHandler()->getServerPublicKeyData();

		// execute hook with just settings and public key information.
		$this->executeHook(self::PWLESS_FLOW_PWLESSINFO, true, $data);

        $data[PWLESS_API_PARAM_SUCCESS] = true;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
		return $this->response($res, 200, $data);
    }

    /**
     * Returns the information about the requesting user, including devices and keys.
     * method GET
     * url /pwless/me
	 * params - none
     */
    function myInfo ($req, $res, $args) {
        global $pwlessauth_user_id;
		global $pwlessauth_user_key;
        global $pwlessauth_user_info;
        $data = array();

        // fetching user data (including key information)
        $result = $this->dbHandler->getUserById($pwlessauth_user_id, true);
        if ($result === false) {
			$data = $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_RETRIEVE_DATA, "Unable to retrieve information from the user.");
			$this->executeHook(self::PWLESS_FLOW_MYINFO, false, "Unable to retrieve information from the user.");
        } else {
            $data[PWLESS_API_PARAM_SUCCESS] = true;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
			$data[PWLESS_API_PARAM_USER_ID] = $pwlessauth_user_id;
			$data[PWLESS_API_PARAM_KEY_ID] = $pwlessauth_user_key;
            $data[PWLESS_API_PARAM_USER] = $result;
			$this->executeHook(self::PWLESS_FLOW_MYINFO, true, $result);
        }
        return $this->response($res, 200, $data);
    }


    /*
     * --------------------- SETTINGS METHODS ----------------------
     */


    /**
     * Returns all the user settings for the authenticated user.
     * method GET
     * url /pwless/settings
	 * params - none
     */
	function getUserSettings($req, $res, $args) {
        global $pwlessauth_user_id;
        $data = array();

        // fetching settings data
        $result = $this->dbHandler->getUserSettings($pwlessauth_user_id);
		$status = 200;
		$data[PWLESS_API_PARAM_SUCCESS] = true;
		$data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
		$data[PWLESS_API_PARAM_SETTINGS] = $result;

		$this->executeHook(self::PWLESS_FLOW_GET_SETTINGS, true, $result);
        return $this->response($res, $status, $data);
	}

    /**
     * Returns a concrete user setting for the authenticated user, specified in the URL.
     * method GET
     * url /pwless/settings/{setting}
	 * params - none
     */
	function getUserSetting($req, $res, $args) {
        global $pwlessauth_user_id;
		$setting = $args[PWLESS_API_PARAM_SETTING];
        $data = array();

        // fetching settings data
        $result = $this->dbHandler->getUserSetting($pwlessauth_user_id, $setting);
		$status = 200;
        if ($result === false) {
			$status = 400;
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_UNABLE_RETRIEVE_DATA;
            $data[PWLESS_API_PARAM_MESSAGE] = "Unable to retrieve setting ".$setting." for the user.";

			$this->executeHook(self::PWLESS_FLOW_GET_SETTING, false, "Unable to retrieve setting ".$setting." for the user.");
        } else {
            $data[PWLESS_API_PARAM_SUCCESS] = true;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
            $data[PWLESS_API_PARAM_SETTING] = $result;

			$this->executeHook(self::PWLESS_FLOW_GET_SETTING, true, $result);
        }
        return $this->response($res, $status, $data);
	}

    /**
     * Sets the value of a concrete user setting for the authenticated user, specified in the URL. If the setting
	 * already existed, it will be overwritten
     * method POST
     * url /pwless/settings/{setting}
	 * params - value
     */
	function setUserSetting($req, $res, $args) {
        global $pwlessauth_user_id;

		// check for required params
        $requestParams = $this->getParametersFromRequest($req);
        if ($missingParams = $this->missingParametersForRequest($res, $requestParams,
        array(PWLESS_API_PARAM_VALUE))) {
			$result = $this->missingParametersResponse($missingParams);
			$this->executeHook(self::PWLESS_FLOW_SET_SETTING, false, "Missing parameters for request");
			return $this->response($res, 400, $result);
		}

        // perform setting operation
		$setting = $args[PWLESS_API_PARAM_SETTING];
		$value = $requestParams[PWLESS_API_PARAM_VALUE];
        $data = array();
		$result = $this->dbHandler->setUserSetting($pwlessauth_user_id, $setting, $value);
		$status = 200;
        if ($result === false) {
			$status = 400;
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_UNABLE_MODIFY_DATA;
            $data[PWLESS_API_PARAM_MESSAGE] = "Unable to set setting ".$setting." to value ".$value.".";

			$this->executeHook(self::PWLESS_FLOW_SET_SETTING, false, "Unable to set setting ".$setting." to value ".$value.".");
        } else {
            $data[PWLESS_API_PARAM_SUCCESS] = true;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
			$settingObject = array(
				PWLESS_API_PARAM_USER_ID => $pwlessauth_user_id,
				PWLESS_API_PARAM_SETTING => $setting,
				PWLESS_API_PARAM_VALUE => $value
			);
			$data[PWLESS_API_PARAM_SETTING] = $settingObject;

			$this->executeHook(self::PWLESS_FLOW_SET_SETTING, true, $settingObject);
        }
        return $this->response($res, $status, $data);
	}

    /**
     * Deletes a concrete user setting for the authenticated user, specified in the URL.
     * method DELETE
     * url /pwless/settings/{setting}
	 * params - none
     */
	function deleteUserSetting($req, $res, $args) {
        global $pwlessauth_user_id;

        // perform setting operation
		$setting = $args[PWLESS_API_PARAM_SETTING];
        $data = array();
		$result = $this->dbHandler->delUserSetting($pwlessauth_user_id, $setting);
		$status = 200;
        if ($result === false) {
			$status = 400;
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_UNABLE_MODIFY_DATA;
            $data[PWLESS_API_PARAM_MESSAGE] = "Unable to delete setting ".$setting.".";

			$this->executeHook(self::PWLESS_FLOW_DEL_SETTING, false, "Unable to delete setting ".$setting.".");
        } else {
            $data[PWLESS_API_PARAM_SUCCESS] = true;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;

			$this->executeHook(self::PWLESS_FLOW_DEL_SETTING, true, "Successfully deleted setting ".$setting.".");
        }
        return $this->response($res, $status, $data);
	}

    /*
     * ------------------------ AUXILIARY METHODS ------------------------
     */

    /**
     * Returns the parameters for a given request.
     */
    public function getParametersFromRequest($req) {
        if ($req->isGet()) {
            $json = $req->getQueryParams();
        } else {
            $json = $req->getParsedBody();
        }
        if ($json === false || $json === null) { return array(); }
        return $json;
    }

    /**
     * Verifying required params posted or not
     */
    public function missingParametersForRequest($res, $requestParams, $requiredFields) {
        $error = false;
        $errorFields = "";

        foreach ($requiredFields as $field) {
            if (!isset($requestParams[$field]) || strlen(trim($requestParams[$field])) <= 0) {
                $error = true;
                $errorFields .= $field . ', ';
            }
        }

        if ($error) { return substr($errorFields, 0, -2); }
        else { return null; }
    }

	/**
	 * Calls a hook with the given success indication and arguments, if the hook's been defined.
	 * @param String $hook		The identifier for the hook to invoke.
	 * @param Bool	 $success	Indication of success or failure for the operation
	 * @param Mixed	 $data		Data for the hook (depends on the hook)
	 */
	function executeHook($flow, $success, $data) {
		if (array_key_exists($flow, $this->hooks) && is_callable($this->hooks[$flow])) {
			call_user_func_array($this->hooks[$flow], array($success, $data));
		}
	}

    /**
     * Returns a "bad request" 400 response with the given error code and message.
     * @param PSR-7 $res Response routing object
     * @param Int $errorCode Error code (one of PWLESS_ERROR_CODE_*)
     * @param String $errorMsg Human readable error message.
     */
    public function badResponse($errorCode = PWLESS_ERROR_CODE_UNDEFINED_ERROR, $errorMsg = "") {
        $data = array();
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = $errorCode;
        $data[PWLESS_API_PARAM_MESSAGE] = $errorMsg;
		return $data;
    }

    /**
     * Returns a "missing validation code" 400 response with the given missing parameters string.
     * @param PSR-7 $res Response routing object
     * @param String $parameters A string containing a description of the parameters missing
     */
    public function missingParametersResponse($parameters) {
        $data = array();
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_MISSING_OR_EMPTY_PARAMETERS;
        $data[PWLESS_API_PARAM_MESSAGE] = 'Required field(s) ' . $parameters . ' missing or empty';
		return $data;
    }

    /**
     * Returns a "invalid code" 400 response.
     * @param PSR-7 $res Response routing object
     */
    function badVerificationCodeResponse() {
        $data = array();
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_INVALID_SECURITY_CODE;
        $data[PWLESS_API_PARAM_MESSAGE] = 'Invalid code. Unable to verify the authenticity of the operation.';
		return $data;
    }

    /**
     * Returns a "account invalid" 401 response with the given missing parameters string.
     * @param PSR-7 $res Response routing object
     * @param String $parameters A string containing a description of the parameters missing
     */
    function accountInvalidResponse() {
        $data = array();
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_ACCOUNT_NEEDS_ACTIVATION;
        $data[PWLESS_API_PARAM_MESSAGE] = 'Your user account is invalid. It has not been activated or has been disabled.';
		return $data;
	}

    /**
     * Returns a "account invalid" 401 response with the given missing parameters string.
     * @param PSR-7 $res Response routing object
     * @param String $message Custom message to specify. If ommited, message will be "Operation performed successfully.".
     */
    public function simpleSuccessfulResponse($message = "Operation performed successfully.") {
        $data = array();
        $data[PWLESS_API_PARAM_SUCCESS] = true;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
        $data[PWLESS_API_PARAM_MESSAGE] = $message;
        return $data;
    }

    /**
     * Returns a "user successfully registered" response for the First Device Registration Flow.
     */
    function userSuccessfullyRegisteredResponse($userAndKeyData, $securityNonceSigned) {
        $data = array();

        // general
        $data[PWLESS_API_PARAM_SUCCESS] = true;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
        $data[PWLESS_API_PARAM_MESSAGE] = "You are successfully registered";
        if ($securityNonceSigned !== false) { $data[PWLESS_API_PARAM_SEC_NONCE_SIGNED] = $securityNonceSigned; }

        // user data
        $data[PWLESS_API_PARAM_USER] = $userAndKeyData;
		// key data
		if (array_key_exists(PWLESS_API_PARAM_KEY, $userAndKeyData)) {
			$data[PWLESS_API_PARAM_KEY] = $userAndKeyData[PWLESS_API_PARAM_KEY];
		}
        return $data;
    }

    /**
     * Returns a bad request response (400), with a concrete error code and message.
     */
    function badRequestResponse($code = PWLESS_ERROR_CODE_BAD_REQUEST, $message = "Unable to process request. Bad request.") {
        $data = array();

        // general
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = $code;
        $data[PWLESS_API_PARAM_MESSAGE] = $message;
        return $data;
    }

    /**
     * Returns a successful response (200), with a concrete error code and message.
     */
    function requestSucceededResponse($code = PWLESS_ERROR_CODE_SUCCESS, $message = "Operation completed successfully.") {
        $data = array();

        // general
        $data[PWLESS_API_PARAM_SUCCESS] = true;
        $data[PWLESS_API_PARAM_CODE] = $code;
        $data[PWLESS_API_PARAM_MESSAGE] = $message;
        return $data;
    }

    /**
     * Returns a "code validation required" response.
     */
    function codeValidationRequiredResponse($secNonceSigned) {
        $data = array();

        // general
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_CODE_VALIDATION_REQUIRED;
        if ($secNonceSigned !== false) { $data[PWLESS_API_PARAM_SEC_NONCE_SIGNED] = $secNonceSigned; }
        return $data;
    }

    /**
     * Echoing json response to client
     * @param PSR-7 $res Response routing object
     * @param String $statusCode Http response code
     * @param Array $data Json response data object
     */
    function response($res, $statusCode, $data) {
        // setting response content type to json
        $newResponse = $res->withHeader('Content-type', 'application/json');
        // return response
        return $newResponse->withStatus($statusCode)->write(json_encode($data));
    }

    /**
     * Checks the existence of a security nonce and, if the server accepts it, signs it and returns it.
     */
    function securityTokenSignedIfAvailable($requestParams) {
        $securityNonceSigned = false;
        $securityNonceRequired = $this->getValueForSetting(PWLESS_SETTING_USE_SECURITY_NONCE);
        if ($securityNonceRequired && isset($requestParams[PWLESS_API_PARAM_SEC_NONCE])) {
            $secNonce = $requestParams[PWLESS_API_PARAM_SEC_NONCE];
            $securityNonceSigned = $this->privateEncryptionHandler()->sign_message($secNonce);
        }
        return $securityNonceSigned;
    }
}
?>
