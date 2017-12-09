<?php

/**
 * Class to handle all db operations
 * This class will have CRUD methods for database tables
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Database\Mysql;

require_once (__DIR__.'/../../Config/Config.php');

use \PasswordLessAuth\Encryption\EncryptionConfiguration;
use \PasswordLessAuth\Encryption\EncryptionHandler;
use \PasswordLessAuth\Mail\MailHandler;
use \PasswordLessAuth\Database\DbHandler;
use \PasswordLessAuth\Database\Mysql\MySQLDbConnect;

class MySQLDbHandler implements DbHandler {
	// static properties and names
	static public $pwLessUsersTable = "pwless_users";
	static public $pwLessDevicesTable = "pwless_devices";
	static public $pwLessSettingsTable = "pwless_settings";


    // variables
    private $conn;
    private $mailHandler;

    public function __construct($dbHost, $dbUsername, $dbPassword, $dbName, $dbPort = '3306') {
        // opening db connection
        $db = new MySQLDbConnect($dbHost, $dbUsername, $dbPassword, $dbName, $dbPort);
        $this->conn = $db->connect();
        $this->mailHandler = new MailHandler(null); 
    }

    /**
     * Creates a new user, and associated device and key entry with the given public key data.
     * @param String $email 	            User email
     * @param String $key_data              User public key of the private-public key pair.
     * @param String $key_type              Type of public key (one of PWLESS_KEY_TYPE_*.
     * @param String $key_length            Length of public key (256, 384, 1024, 2048, 4096...).
     * @param String $device_info           A string identifying the device.
     * @param String $signature_algorithm   Signature algorithm used by the device.
     * @param String $securityNonceSigned   Security nonce signed to include in the response.
     */
    public function registerUser($email, $key_data, $key_type, $key_length, $device_info, $signature_algorithm, $securityNonceSigned, $mustConfirmEmail) {
        $userData = $this->getUserByEmail($email);
        // First check if user already existed in db
        if ($userData === false) { // First Device Registration. Generate user entry, login and api tokens.
			$status = $mustConfirmEmail ? PWLESS_ACCOUNT_UNCONFIRMED : PWLESS_ACCOUNT_CONFIRMED;

            // Now verify the key
            if (!$this->verifyKeyValidity($key_data, $key_type, $key_length, $signature_algorithm)) {
                return $this->badRequestResponse(PWLESS_ERROR_CODE_INVALID_KEY, "Sorry, the provided key is invalid or in a unsupported format.");
            }

            // start transaction (atomic insert of user + device/key)
            $this->startTransaction();
            // insert user query
            $newUserId = $this->addUserEntry($email, $status);

            // Check for successful insertion
            if ($newUserId !== false) { // User successfully inserted: insert device/key entry.
                // insert device/key query.
                $newDeviceId = $this->addUserDeviceAndKeyEntry($newUserId, $key_data, $key_type, $device_info, $key_length, $signature_algorithm);
                if ($newDeviceId !== false) { // success!
                    $this->commitTransaction();
                    return $this->userSuccessfullyRegisteredResponse($newUserId, $email, $newDeviceId, $securityNonceSigned);
                } else {
                    $this->rollbackTransaction();
                    return $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_REGISTER_USER, "Error adding user key and device entry.");
                }
            } else { // Failed to create user: rollback
                $this->rollbackTransaction();
                return $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_REGISTER_USER, "Error adding new user entry.");
            }

        } else { // User with same email already existed in the db, no security code. Start "Add Device and Key" flow.
            $securityCode = $this->securityCodeForUserWithId($userData[PWLESS_API_PARAM_ID]);
            if ($this->mailHandler->sendSecurityCodeEmail($email, $securityCode)) {
                return $this->codeValidationRequiredResponse($securityNonceSigned);
            } else {
                return $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_SEND_MAIL, "Error sending security code email for device registration.");
            }
        }
    }

    /**
     * Creates a new user, and associated device and key entry with the given public key data.
     * @param String $email 	            User email
     * @param String $key_data              User public key of the private-public key pair.
     * @param String $key_type              Type of public key (one of PWLESS_KEY_TYPE_*.
     * @param String $key_length            Length of public key (256, 384, 1024, 2048, 4096...).
     * @param String $device_info           A string identifying the device.
     * @param String $signature_algorithm   Signature algorithm used by the device.
     * @param String $security_code         Security code to validate the addition of the device to the user's account.
     */
    public function addDeviceToUser($email, $key_data, $key_type, $key_length, $device_info, $signature_algorithm, $security_code) {
        $userData = $this->getUserByEmail($email);

        // First check if user already existed in db
        if ($security_code && $userData) {  // User is valid and we have a valid security code.
            $userId = $userData[PWLESS_API_PARAM_ID];

            // Now verify the key
            if (!$this->verifyKeyValidity($key_data, $key_type, $key_length, $signature_algorithm)) {
                return $this->badRequestResponse(PWLESS_ERROR_CODE_INVALID_KEY, "Sorry, the provided key is invalid or in a unsupported format.");
            }

            // Check if the security code was correct.
            $correctSecurityCode = $this->securityCodeForUserWithId($userData[PWLESS_API_PARAM_ID]);
            // Despite the result, change the security code.
            $this->updateUserSecurityCode($userId);
            if ($security_code === $correctSecurityCode) {
                $newDeviceId = $this->addUserDeviceAndKeyEntry($userId, $key_data, $key_type, $device_info, $key_length, $signature_algorithm);
                if ($newDeviceId !== false) {
                    return $this->userSuccessfullyRegisteredResponse($userId, $email, $newDeviceId, $securityNonceSigned);
                } else {
                    return $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_REGISTER_USER, "Unable to register device for user. Error adding new device key for the user.");
                }
            } else {
                return $this->badRequestResponse(PWLESS_ERROR_CODE_INVALID_SECURITY_CODE, "Unable to register device for user. Invalid security code.");
            }
        } else {
            return $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_REGISTER_USER, "Unable to register user. Unexpected error.");
        }
    }

    /**
     * Inserts a new user entry.
     * @param String $email                 Email of the user to create.
     * @param Integer $status               The new status for the user to be created..
     */
    function addUserEntry($email, $status) {
        $security_code = EncryptionHandler::generate_security_code();
        $stmt = $this->conn->prepare("INSERT INTO ".self::$pwLessUsersTable."(email, created_at, status, security_code) values(?, now(), ?, ?)");
        $stmt->bind_param("sis", $email, $status, $security_code);
        $result = $stmt->execute();
        $newUserId = $this->conn->insert_id;
        $stmt->close();

        if ($result && $newUserId) { return $newUserId; }
        else { return false; }
    }

    /**
     * Inserts a new device / key entry for a user with some information.
     * @param String $user_id               ID of the user to associate the device/key entry to.
     * @param String $key_data              User public key of the private-public key pair.
     * @param String $key_type              Type of public key (one of PWLESS_KEY_TYPE_*.
     * @param String $key_length            Length of public key (256, 384, 1024, 2048, 4096...).
     * @param String $device_info           A string identifying the device.
     * @param String $signature_algorithm   Signature algorithm used by the device.
     */
    function addUserDeviceAndKeyEntry($userId, $key_data, $key_type, $device_info, $key_length, $signature_algorithm) {
        // generate tokens
        $access_token = EncryptionHandler::generate_token($userId);
        $login_token = EncryptionHandler::generate_token($userId);

        $stmt = $this->conn->prepare("INSERT INTO ".self::$pwLessDevicesTable."(user_id, key_data, login_token, access_token, key_type, device_info, key_length, signature_algorithm, created_at) values(?, ?, ?, ?, ?, ?, ?, ?, now())");
        $stmt->bind_param("isssssis", $userId, $key_data, $login_token, $access_token, $key_type, $device_info, $key_length, $signature_algorithm);
        $result = $stmt->execute();
        $newKeyId = $this->conn->insert_id;
        $stmt->close();

        if ($result && $newKeyId) { return $newKeyId; }
        else { return false; }
    }

    /**
     * Updates the user's security code. Returns the code on a successful operation, or false if an error happened.
     * @param String $email 	            User email
     * @param String $key_id                ID of the key to delete.
     * @param String $security_code         Security code to validate the deletion of the device in the user's account.
     */
    public function deleteUserDeviceAndKeyEntry($email, $key_id, $security_code) {
        $userData = $this->getUserByEmail($email);
        if ($userData === false) { return $this->badRequestResponse(PWLESS_ERROR_CODE_IDENTITY_VALIDATION_FAILED, "Unable to delete device and key for user. I was unable to validate the identity of the user and device."); }
        $userId = $userData[PWLESS_API_PARAM_ID];
        $keyData = $this->getFullKeyInformationForUserWithId($userId, $key_id);
        if ($keyData === false) { return $this->badRequestResponse(PWLESS_ERROR_CODE_IDENTITY_VALIDATION_FAILED, "Unable to delete device and key for user. I was unable to validate the identity of the user and device."); }
        $keyId = $keyData[PWLESS_API_PARAM_ID];

        // First check if we have a security code
        $correctSecurityCode = $this->securityCodeForUserWithId($userData[PWLESS_API_PARAM_ID]);
        if ($security_code !== false) {  // if we have a valid security code.
            // Despite the result, change the security code.
            $this->updateUserSecurityCode($userId);
            // Check if the security code was correct.
            if ($security_code === $correctSecurityCode) {
                if ($this->deleteKeyEntry($keyId, $userId)) { return $this->requestSucceededResponse(); }
                else { return $this->badRequestResponse(PWLESS_ERROR_CODE_UNDEFINED_ERROR, "Unable to delete device and key for user. An error happened while deleting the device and key entry."); }
            } else { return $this->badRequestResponse(PWLESS_ERROR_CODE_INVALID_SECURITY_CODE, "Unable to delete device and key for user. Invalid security code."); }
        } else {
            // send email to user with security code.
            if ($this->mailHandler->sendSecurityCodeEmail($email, $correctSecurityCode)) {
                return $this->codeValidationRequiredResponse(false);
            } else { return $this->badRequestResponse(PWLESS_ERROR_CODE_UNABLE_SEND_MAIL, "Unable to delete device and key for user. Unable to send security confirmation code to the user."); }
        }
    }

    /**
     * Deletes a key entry from the devices and key table.
     * @param String $key_id                ID of the key to delete.
     * @param String $user_id               ID of the user associated to this device/key entry.
     */
    public function deleteKeyEntry($key_id, $user_id) {
        $stmt = $this->conn->prepare("DELETE FROM ".self::$pwLessDevicesTable." WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $key_id, $user_id);
        $result = $stmt->execute();
        $stmt->close();
        return $result;
    }

    /**
     * Updates the user's security code. Returns the code on a successful operation, or false if an error happened.
     * @param String $userId               ID of the user to associate the device/key entry to.
     */
    function updateUserSecurityCode($userId) {
        $security_code = EncryptionHandler::generate_security_code();
        $stmt = $this->conn->prepare("UPDATE ".self::$pwLessUsersTable." SET security_code = ? WHERE id = ?");
        $stmt->bind_param("si", $security_code, $userId);
        $result = $stmt->execute();
        $stmt->close();
        return $result;

    }

    /**
     * Checks the key validity of a given key for the registration of a new user or device.
     */
    function verifyKeyValidity($keyData, $keyType, $keyLength, $signatureAlgorithm) {
        $config = new EncryptionConfiguration($keyData, $keyType, $keyLength, $signatureAlgorithm, PWLESS_KEY_TYPE_PUBLIC);
        $eh = new EncryptionHandler($config);
        return $eh->checkPublicKeyIsValid();
    }

	/**
	 * Generates a login request for the given user if it exists and its valid.
     * @param String $email 			User email
     * @param String $security_nonce	A plain text security nonce to be signed by the server.
	 * @return the login token for the user to sign and send a /login_validate request.
	 */
	public function generateLoginRequest($email, $key_id) {
        $keyData = $this->getFullKeyInformationForUserWithEmail($email, $key_id);
        if ($keyData !== false) { return $keyData[PWLESS_API_PARAM_LOGIN_TOKEN]; }
		else { return false; }
	}

    /**
     * Validates the user login after a login request.
     * @param String $email 	      User email
     * @param String $login_signature The login key signature returned by the user to the login request.
     * @returns mixed an associative array with the user's data if the login validation succeed, false otherwise
     */
    public function validateLogin($email, $key_id, $login_token_signed, $authenticationMode) {
        // get user data and verify that the account has been activated or less than 7 days have passed.
        $userData = $this->getUserByEmail($email);

        // get user device key and validate signature.
        $userKey = $this->getFullKeyInformationForUserWithEmail($email, $key_id);
	    if ($userData && $userKey) { // key and user exist? get key data
	        $keyData = $userKey[PWLESS_API_PARAM_KEY_DATA];
            $keyType = $userKey[PWLESS_API_PARAM_KEY_TYPE];
            $keyLength = $userKey[PWLESS_API_PARAM_KEY_LENGTH];
            $signatureAlgorithm = $userKey[PWLESS_API_PARAM_SIGNATURE_ALGORITHM];

		    $config = new EncryptionConfiguration($keyData, $keyType, $keyLength, $signatureAlgorithm);
            $eh = new EncryptionHandler($config);
		    if ($eh->validate_signature($userKey["login_token"], $login_token_signed)) {  // login_token valid?
                // change and store login key
                $nextLoginKey = $this->newLoginKeyForUserKeyEntry($userData[PWLESS_API_PARAM_ID], $key_id);
                if ($nextLoginKey !== false) {
                    // create the data that we are going to return to the user just with the interesting info.
                    $result = $this->requestSucceededResponse();

                    // user and device key info.
                    $result[PWLESS_API_PARAM_USER] = $userData;
                    $result[PWLESS_API_PARAM_KEY] = $userKey;

                    // auth data
                    $auth = array();
                    $auth[PWLESS_API_PARAM_ACCESS_TOKEN] = $userKey[PWLESS_API_PARAM_ACCESS_TOKEN];
                    if ($authenticationMode == PWLESS_AUTHENTICATION_MODE_STRICT) {
                        $auth[PWLESS_API_PARAM_EXPIRES] = $this->addMinutesToDate(60); // 1h
                    } else {
                        $auth[PWLESS_API_PARAM_EXPIRES] = $this->addMinutesToDate(1440); // 24h
                    }
                    $auth[PWLESS_API_PARAM_NEXT_LOGIN_TOKEN] = $nextLoginKey;
                    $result[PWLESS_API_PARAM_AUTH] = $auth;

                    return $result;
                }
		    }
	    }
	    return $this->badRequestResponse(PWLESS_ERROR_CODE_IDENTITY_VALIDATION_FAILED, "Unable to get access token. I was unable to validate the identity of the user and device.");
    }

    /**
     * Checking for user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    public function userExists($email) {
        $stmt = $this->conn->prepare("SELECT id from ".self::$pwLessUsersTable." WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $stmt->store_result();
        $num_rows = $stmt->num_rows;
        $stmt->close();
        return $num_rows > 0;
    }

    /**
     * Fetching user data by email
     * @param String $email                     User email
     * @param Bool   $include_key_information   If true, all public key information will also be retrieved.
     */
    public function getUserByEmail($email, $include_key_information = false) {
	    if (empty($email)) return false;
        $stmt = $this->conn->prepare("SELECT id, email, created_at, status FROM ".self::$pwLessUsersTable." WHERE email = ?");
        $stmt->bind_param("s", $email);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id, $email, $created_at, $status);
            if ($stmt->fetch()) {
                $user = array();
                $user[PWLESS_API_PARAM_ID] = $user_id;
                $user[PWLESS_API_PARAM_EMAIL] = $email;
                $user[PWLESS_API_PARAM_CREATED_AT] = $created_at;
                $user[PWLESS_API_PARAM_STATUS] = $status;
                $stmt->close();
                // if we don't need to retrieve the key information, that's all.
                if ($include_key_information) {
                    $keysArray = $this->getKeysForUserWithId($user_id);
                    $user[PWLESS_API_PARAM_KEYS] = $keysArray;
                }
                return $user;
            }
        }
        return false;
    }

    /**
     * Fetching user data by email
     * @param String $email                     User email
     * @param Bool   $include_key_information   If true, all public key information will also be retrieved.
     */
    public function getUserById($user_id, $include_key_information = false) {
	    if (empty($user_id)) return false;
        $stmt = $this->conn->prepare("SELECT id, email, created_at, status FROM ".self::$pwLessUsersTable." WHERE id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $stmt->bind_result($retrieved_id, $email, $status, $created_at);
            if ($stmt->fetch()) {
                $user = array();
                $user[PWLESS_API_PARAM_ID] = $user_id;
                $user[PWLESS_API_PARAM_EMAIL] = $email;
                $user[PWLESS_API_PARAM_CREATED_AT] = $created_at;
                $user[PWLESS_API_PARAM_STATUS] = $status;
                $stmt->close();
                // if we don't need to retrieve the key information, that's all.
                if ($include_key_information) {
                    $keysArray = $this->getKeysForUserWithId($user_id);
                    $user[PWLESS_API_PARAM_KEYS] = $keysArray;
                }
                return $user;
            }
        }
        return false;
    }

    /**
     * Fetching the devices and keys for a user
     * @param String $user_id user id primary key in user table
     * @returns array The access token for that user and that key id.
     */
    public function getKeysForUserWithId($user_id) {
        $keysArray = array();
        $stmt = $this->conn->prepare("SELECT id, key_data, key_type, device_info, key_length, signature_algorithm, created_at FROM ".self::$pwLessDevicesTable." WHERE user_id = ?");
        $stmt->bind_param("i", $user_id);
        if ($stmt->execute()) {
            $stmt->bind_result($key_id, $key_data, $key_type, $device_info, $key_size, $signature_algorithm, $key_created_at);
            while ($stmt->fetch()) {
                $temp = array();
                $temp[PWLESS_API_PARAM_ID] = $key_id;
                $temp[PWLESS_API_PARAM_USER_ID] = $user_id;
                $temp[PWLESS_API_PARAM_KEY_DATA] = $key_data;
                $temp[PWLESS_API_PARAM_KEY_TYPE] = $key_type;
                $temp[PWLESS_API_PARAM_DEVICE_INFO] = $device_info;
                $temp[PWLESS_API_PARAM_KEY_LENGTH] = $key_size;
                $temp[PWLESS_API_PARAM_SIGNATURE_ALGORITHM] = $signature_algorithm;
                $temp[PWLESS_API_PARAM_CREATED_AT] = $key_created_at;
                $keysArray[] = $temp;
            }
        }
        return $keysArray;
    }


    /**
     * Gets the key information from concrete device of a concrete user with a email and key_id. Do not use this method
     * to return information to the user, as it outputs private data.
     * @param Int $email    user email
     * @param Int $key_id   key id primary key in user table
     * @returns an associative array containing the key information..
     */
    public function getFullKeyInformationForUserWithEmail($email, $key_id) {
        $userData = $this->getUserByEmail($email);
        if ($userData !== false && isset($userData[PWLESS_API_PARAM_ID])) {
            return $this->getFullKeyInformationForUserWithId($userData[PWLESS_API_PARAM_ID], $key_id);
        }
        return false;
    }
    /**
     * Gets the key information from concrete device of a concrete user with a user_id and key_id. Do not use this method
     * to return information to the user, as it outputs private data.
     * @param Int $user_id  user id primary key in user table
     * @param Int $key_id   key id primary key in user table
     * @returns an associative array containing the key information..
     */
    public function getFullKeyInformationForUserWithId($user_id, $key_id) {
        if (!$user_id || !$key_id) { return false; }

        $stmt = $this->conn->prepare("SELECT id, key_data, key_type, device_info, key_length, login_token, access_token, signature_algorithm, created_at FROM ".self::$pwLessDevicesTable." WHERE user_id = ? AND id = ?");
        $stmt->bind_param("ii", $user_id, $key_id);
        if ($stmt->execute()) {
            $stmt->bind_result($key_id, $key_data, $key_type, $device_info, $key_size, $login_token, $access_token, $signature_algorithm, $key_created_at);
            if ($stmt->fetch()) {
                $temp = array();
                $temp[PWLESS_API_PARAM_ID] = $key_id;
                $temp[PWLESS_API_PARAM_USER_ID] = $user_id;
                $temp[PWLESS_API_PARAM_KEY_DATA] = $key_data;
                $temp[PWLESS_API_PARAM_KEY_TYPE] = $key_type;
                $temp[PWLESS_API_PARAM_DEVICE_INFO] = $device_info;
                $temp[PWLESS_API_PARAM_KEY_LENGTH] = $key_size;
                $temp[PWLESS_API_PARAM_LOGIN_TOKEN] = $login_token;
                $temp[PWLESS_API_PARAM_ACCESS_TOKEN] = $access_token;
                $temp[PWLESS_API_PARAM_SIGNATURE_ALGORITHM] = $signature_algorithm;
                $temp[PWLESS_API_PARAM_REGISTERED] = $key_created_at;
                return $temp;
            }
        }
        return false;
    }

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     * @param String $key_id  key id primary key in user table
     * @returns String The access token for that user and that key id.
     */
    public function getAccessTokenById($user_id, $key_id) {
        $stmt = $this->conn->prepare("SELECT access_token FROM ".self::$pwLessDevicesTable." WHERE id = ? AND user_id = ?");
        $stmt->bind_param("ii", $key_id, $user_id);
        if ($stmt->execute()) {
            $stmt->bind_result($access_token);
            $stmt->close();
            return $access_token;
        } else {
            return false;
        }
    }

    /**
     * Fetching user id by access token
     * @param String $access_token user access token
     */
    public function getUserIdForAccessToken($access_token) {
        $stmt = $this->conn->prepare("SELECT user_id FROM ".self::$pwLessUsersTable." WHERE access_token = ?");
        $stmt->bind_param("s", $access_token);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id);
            $stmt->fetch();
            $stmt->close();
            return $user_id;
        } else {
            return false;
        }
    }

    /**
     * Retrieves the security code for a user with certain ID
     * @param Int userId    The ID of the user to retrieve the security code from.
     */
    function securityCodeForUserWithId($userId) {
        $stmt = $this->conn->prepare("SELECT security_code FROM ".self::$pwLessUsersTable." WHERE id = ?");
        $stmt->bind_param("i", $userId);
        if ($stmt->execute()) {
            $stmt->bind_result($securityCode);
            $securityCode = null;
            $stmt->fetch();
            $stmt->close();
            return $securityCode;
        } else {
            return false;
        }
    }

    /**
     * Validates a user API key and returns the ID of the user if it's valid, false otherwise.
	 * AN API key will validate if it's valid for a user with status = confirmed or status = unconfirmed created less than a week ago.
     * @param String $access_token user api key
     * @return mixed the ID of the user if API key was valid, false otherwise.
     */
    public function validUserIdForAccessToken($access_token) {
        $stmt = $this->conn->prepare("SELECT ".self::$pwLessUsersTable.".id, ".self::$pwLessUsersTable.".created_at, ".self::$pwLessUsersTable.".status from ".self::$pwLessUsersTable.", ".self::$pwLessDevicesTable." WHERE ".self::$pwLessUsersTable.".id = ".self::$pwLessDevicesTable.".user_id AND ".self::$pwLessDevicesTable.".access_token = ?");
        $stmt->bind_param("s", $access_token);
        if ($stmt->execute()) {
            $stmt->bind_result($user_id, $created_at, $status);
            if ($stmt->fetch()) {
                $stmt->close();
                // check status.
                if ($status == PWLESS_ACCOUNT_CONFIRMED) { // Account confirmed, API key valid. Return user id and proceed.
                    return $user_id;
                } else if ($status == PWLESS_ACCOUNT_UNCONFIRMED) { // Account unconfirmed, let the user use the backend if less than a week has passed.
                    $creation_timestamp = strtotime($created_at);
                    $current_timestamp = time();
                    if (($current_timestamp - $creation_timestamp) < PWLESS_UNCONFIRMED_ACCOUNT_USE_TIME) { // unconfirmed account use time not expired yet.
                        return $user_id;
                    } // else will return false.
                } // else will return false.
            }
		}
		return false;
    }

    /**
	 * Generates a new login token, associates it with the user and returns it if successful.
	 * @param String $email	email of the user
	 * @returns the newly generated login token or false if it couldn't be generated and inserted in the database.
	 */
	public function newLoginKeyForUserKeyEntry($user_id, $key_id) {
		$new_login_token = EncryptionHandler::generate_token();
        $stmt = $this->conn->prepare("UPDATE ".self::$pwLessDevicesTable." SET login_token = ? WHERE id = ? AND user_id = ?");
        $stmt->bind_param("sii", $new_login_token, $user_id, $key_id);
        $result = $stmt->execute();
        $stmt->close();

	    if ($result === false) { return false; }
	    else { return $new_login_token; }
	}

	/**
	 * Sets the status of a user identified with an id to a given value.
	 * @param Int $user_id	ID of the user
	 * @param Int $status 	new status to set.
	 */
	public function setUserStatus($user_id, $status) {
		$stmt = $this->conn->prepare("UPDATE ".self::$pwLessUsersTable." SET status = ? where id = ?");
		$stmt->bind_param("ii", $status, $user_id);
        $result = $stmt->execute();
        $stmt->close();
		return $result;
	}

    /*********************** Auxiliary functions *******************************/

    /**
     * Starts a database transaction. Must be finished by a call to commitTransaction() or rollbackTransaction().
     */
    function startTransaction() {
        $this->conn->query('START TRANSACTION');
    }

    /**
     * Commits a database transaction. Must be called after a call to startTransaction().
     */
    function commitTransaction() {
        $this->conn->query('COMMIT');
    }

    /**
     * Rollbacks a database transaction. Must be called after a call to startTransaction().
     */
    function rollbackTransaction() {
        $this->conn->query('ROLLBACK');
    }

    /**
     * Returns a "user successfully registered" response for the First Device Registration Flow.
     */
    function userSuccessfullyRegisteredResponse($userId, $userEmail, $keyId, $securityNonceSigned) {
        $data = array();

        // get key data or return an error response.
        $keyInfo = $this->getFullKeyInformationForUserWithId($userId, $keyId);
        if ($keyInfo === false) {
            $data[PWLESS_API_PARAM_SUCCESS] = false;
            $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_UNABLE_REGISTER_USER;
            $data[PWLESS_API_PARAM_MESSAGE] = "Unable to register new device and key for user. Key not properly loaded.";
            return $data;
        }

        // general
        $data[PWLESS_API_PARAM_SUCCESS] = true;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_SUCCESS;
        $data[PWLESS_API_PARAM_MESSAGE] = "You are successfully registered";
        if ($securityNonceSigned !== false) { $data[PWLESS_API_PARAM_SEC_NONCE_SIGNED] = $securityNonceSigned; }

        // user data
        $userData = array();
        $userData[PWLESS_API_PARAM_ID] = $userId;
        $userData[PWLESS_API_PARAM_EMAIL] = $userEmail;
        $data[PWLESS_API_PARAM_USER] = $userData;

        // key data
        $keyData = array();
        $keyData[PWLESS_API_PARAM_ID] = $keyInfo[PWLESS_API_PARAM_ID];
        $keyData[PWLESS_API_PARAM_KEY_TYPE] = $keyInfo[PWLESS_API_PARAM_KEY_TYPE];
        $keyData[PWLESS_API_PARAM_SIGNATURE_ALGORITHM] = $keyInfo[PWLESS_API_PARAM_SIGNATURE_ALGORITHM];
        $keyData[PWLESS_API_PARAM_KEY_LENGTH] = $keyInfo[PWLESS_API_PARAM_KEY_LENGTH];
        $keyData[PWLESS_API_PARAM_DEVICE_INFO] = $keyInfo[PWLESS_API_PARAM_DEVICE_INFO];
        $data[PWLESS_API_PARAM_KEY] = $keyData;

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
    function codeValidationRequiredResponse($sec_nonce_signed) {
        $data = array();

        // general
        $data[PWLESS_API_PARAM_SUCCESS] = false;
        $data[PWLESS_API_PARAM_CODE] = PWLESS_ERROR_CODE_CODE_VALIDATION_REQUIRED;
        if ($sec_nonce_signed !== false) { $data[PWLESS_API_PARAM_SEC_NONCE_SIGNED] = $sec_nonce_signed; }
        return $data;
    }

    /**
     * Returns a date past a number of minutes.
     */
    function addMinutesToDate($minutes, $time = null) {
        if (!$time) { $time = new \DateTime(); }
        $time->add(new \DateInterval('PT' . $minutes . 'M'));
        $stamp = $time->format(\DateTime::ISO8601);
        return $stamp;
    }

    /**
     * Returns true if the given date is more than a week in the past from the current date.
     */
    function dateIsMoreThanAWeekInThePast($date) {
        $timestamp = strtotime($date);
        $now = time();
        return ($now - $timestamp > PWLESS_WEEK_IN_SECONDS);
    }

    /**
     * Checks that the user status is valid.
     * The user should be a valid account in a confirmed (PWLESS_ACCOUNT_CONFIRMED) state.
     * @param String $email                 Email of the user to verify.
     * @param String $confirmAccountMode    The confirm account mode for this PasswordLessAuth server.
     */
    public function userStatusIsValid($email, $confirmAccountMode) {
        // check user status
        $userData = $this->getUserByEmail($email);
        if (!$userData) { return false; }

        // disabled or confirmed users get a direct answer
        if ($userData[PWLESS_API_PARAM_STATUS] == PWLESS_ACCOUNT_DISABLED) { return false; }
        if ($userData[PWLESS_API_PARAM_STATUS] == PWLESS_ACCOUNT_CONFIRMED) { return true; }
        else { // user status is unconfirmed (PWLESS_ACCOUNT_UNCONFIRMED)
            if ($confirmAccountMode == PWLESS_CONFIRMATION_EMAIL_NONE) { return true; }
            else if ($confirmAccountMode == PWLESS_CONFIRMATION_EMAIL_LAX) {
                // check creation date for unconfirmed users on lax mode.
                $date = $userData[PWLESS_API_PARAM_CREATED_AT];
                return !$this->dateIsMoreThanAWeekInThePast($date);
            } else { // mode = PWLESS_CONFIRMATION_EMAIL_STRICT
                return false;
            }
        }
    }
    
    /**
     * Sets the mail handler that will be used for operations requiring to send an email to the user.
     * @param Object $mailHandler An instance of mail handler.
     */
    public function setMailHandler($mailHandler) {
        $this->mailHandler = $mailHandler;
    }
    
    /********************************* Initialize database *******************************************/

    /**
     * Initializes the database tables if needed. If the data tables exist, this method will exit.
     * @param Bool $overwrite If true, the tables will recreate, even if they exist. Be careful, this will wipe out all pwLessAuth data.
     */
    public function initializePasswordLessAuthDatabase($overwrite) {
        $needsToCreateUsersTable = false;
        $needsToCreateDevicesTable = false;
        $needsToCreateSettingsTable = false;

        // detect if tables exist
        if ($overwrite === true) {
            if (!$this->conn->query("DROP TABLE IF EXISTS ".self::$pwLessUsersTable.", ".self::$pwLessDevicesTable.", ".self::$pwLessSettingsTable)) {
                die('PasswordLessAuth fatal error: unable to delete old PasswordLessAuth tables: ' . $this->conn->error);
            }
            $needsToCreateUsersTable = true;
            $needsToCreateDevicesTable = true;
        } else {
            if (!$this->tableExists(self::$pwLessUsersTable)) { $needsToCreateUsersTable = true; }
            if (!$this->tableExists(self::$pwLessDevicesTable)) { $needsToCreateDevicesTable = true; }
        }
        
        // create tables if needed
        if ($needsToCreateDevicesTable) {
            $createDevicesQuery = "CREATE TABLE `".self::$pwLessDevicesTable."` (
              `id` int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
              `user_id` int(11) NOT NULL,
              `key_data` text NOT NULL,
              `login_token` varchar(80) NOT NULL,
              `access_token` varchar(80) NOT NULL,
              `key_type` varchar(40) NOT NULL,
              `device_info` varchar(255) NOT NULL,
              `key_length` int(11) NOT NULL,
              `signature_algorithm` varchar(80) NOT NULL,
              `created_at` datetime NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
            if (!$this->conn->query($createDevicesQuery)) {
                die('PasswordLessAuth fatal error: unable to create table for devices: ' . $this->conn->error);
            }
        }
        
        if ($needsToCreateUsersTable) {
            $createUsersQuery = "CREATE TABLE `".self::$pwLessUsersTable."` (
              `id` int(11) NOT NULL AUTO_INCREMENT PRIMARY KEY,
              `email` varchar(255) NOT NULL,
              `created_at` datetime NOT NULL,
              `status` int(1) NOT NULL,
              `security_code` varchar(10) NOT NULL
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8;";            
            if (!$this->conn->query($createUsersQuery)) {
                die('PasswordLessAuth fatal error: unable to create table for users: ' . $this->conn->error);
            }
        }

		if ($needsToCreateSettingsTable) {
			$createSettingsQuery = "CREATE TABLE `".self::$pwLessSettingsTable."` (
			  `user_id` int(11) NOT NULL,
			  `device_id` int(11) DEFAULT NULL,
			  `setting` varchar(255) NOT NULL,
			  `value` varchar(255) NOT NULL,
			  UNIQUE (user_id, device_id, setting)
			) ENGINE=InnoDB DEFAULT CHARSET=utf8;";
			if (!$this->conn->query($createSettingsQuery)) {
                die('PasswordLessAuth fatal error: unable to create table for settings: ' . $this->conn->error);
            }
		}
    }
    
    function tableExists($table) {
        if ($res = $this->conn->query("SHOW TABLES LIKE '$table'")) {
            $exists = $res->num_rows > 0;
            $res->close();
            return $exists;
        } else { return false; }
    }
    
}

?>
