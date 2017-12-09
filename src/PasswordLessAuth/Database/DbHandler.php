<?php
/**
 * Interface for database operations.
 * This class defines CRUD methods for database operations.
 * All DbHandler classes should implement these methods.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Database;

/**
 * The DbHandler interface specifies the common functions every DbHandler for PasswordLessAuth in PHP should implement.
 */
interface DbHandler {
    /**
     * Creates a new user, and associated device and key entry with the given public key data.
     * @param String $email 	            User email
     * @param String $key_data              User public key of the private-public key pair.
     * @param String $key_type              Type of public key (one of PWLESS_KEY_TYPE_*.
     * @param String $key_length            Length of public key (256, 384, 1024, 2048, 4096...).
     * @param String $device_info           A string identifying the device.
     * @param String $signature_algorithm   Signature algorithm used by the device.
     * @param String $securityNonceSigned   Security nonce signed to include in the response.
	 * @param String $mustConfirmEmail		True if the account must be confirmed via email (status = 0 instead of 1)
     */
    public function registerUser($email, $key_data, $key_type, $key_length, $device_info, $signature_algorithm, $securityNonceSigned, $mustConfirmEmail);

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
    public function addDeviceToUser($email, $key_data, $key_type, $key_length, $device_info, $signature_algorithm, $security_code);

    /**
     * Updates the user's security code. Returns the code on a successful operation, or false if an error happened.
     * @param String $email 	            User email
     * @param String $key_id                ID of the key to delete.
     * @param String $security_code         Security code to validate the deletion of the device in the user's account.
     */
    public function deleteUserDeviceAndKeyEntry($email, $key_id, $security_code);

    /**
     * Deletes a key entry from the devices and key table.
     * @param String $key_id                ID of the key to delete.
     * @param String $user_id               ID of the user associated to this device/key entry.
     */
    public function deleteKeyEntry($key_id, $user_id);

	/**
	 * Generates a login request for the given user if it exists and its valid.
     * @param String $email 			User email
     * @param String $security_nonce	A plain text security nonce to be signed by the server.
	 * @return the login token for the user to sign and send a /login_validate request.
	 */
	public function generateLoginRequest($email, $key_id);

    /**
     * Validates the user login after a login request.
     * @param String $email 	      User email
     * @param String $login_signature The login key signature returned by the user to the login request.
     * @returns mixed an associative array with the user's data if the login validation succeed, false otherwise
     */
    public function validateLogin($email, $key_id, $login_token_signed, $authenticationMode);

    /**
     * Checking for user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    public function userExists($email);

    /**
     * Fetching user data by email
     * @param String $email                     User email
     * @param Bool   $include_key_information   If true, all public key information will also be retrieved.
     */
    public function getUserByEmail($email, $include_key_information = false);

    /**
     * Fetching user data by email
     * @param String $email                     User email
     * @param Bool   $include_key_information   If true, all public key information will also be retrieved.
     */
    public function getUserById($user_id, $include_key_information = false);

    /**
     * Fetching the devices and keys for a user
     * @param String $user_id user id primary key in user table
     * @returns array The access token for that user and that key id.
     */
    public function getKeysForUserWithId($user_id);


    /**
     * Gets the key information from concrete device of a concrete user with a email and key_id. Do not use this method
     * to return information to the user, as it outputs private data.
     * @param Int $email    user email
     * @param Int $key_id   key id primary key in user table
     * @returns an associative array containing the key information..
     */
    public function getFullKeyInformationForUserWithEmail($email, $key_id);
    
    /**
     * Gets the key information from concrete device of a concrete user with a user_id and key_id. Do not use this method
     * to return information to the user, as it outputs private data.
     * @param Int $user_id  user id primary key in user table
     * @param Int $key_id   key id primary key in user table
     * @returns an associative array containing the key information..
     */
    public function getFullKeyInformationForUserWithId($user_id, $key_id);

    /**
     * Fetching user api key
     * @param String $user_id user id primary key in user table
     * @param String $key_id  key id primary key in user table
     * @returns String The access token for that user and that key id.
     */
    public function getAccessTokenById($user_id, $key_id);

    /**
     * Fetching user id by access token
     * @param String $access_token user access token
     */
    public function getUserIdForAccessToken($access_token);

    /**
     * Validates a user API key and returns the ID of the user if it's valid, false otherwise.
	 * AN API key will validate if it's valid for a user with status = confirmed or status = unconfirmed created less than a week ago.
     * @param String $access_token user api key
     * @return mixed the ID of the user if API key was valid, false otherwise.
     */
    public function validUserIdForAccessToken($access_token);

    /**
	 * Generates a new login token, associates it with the user and returns it if successful.
	 * @param String $email	email of the user
	 * @returns the newly generated login token or false if it couldn't be generated and inserted in the database.
	 */
	public function newLoginKeyForUserKeyEntry($user_id, $key_id);

	/**
	 * Sets the status of a user identified with an id to a given value.
	 * @param Int $user_id	ID of the user
	 * @param Int $status 	new status to set.
	 */
	public function setUserStatus($user_id, $status);

    /**
     * Checks that the user status is valid.
     * The user should be a valid account in a confirmed (PWLESS_ACCOUNT_CONFIRMED) state.
     * @param String $email                 Email of the user to verify.
     * @param String $confirmAccountMode    The confirm account mode for this PasswordLessAuth server.
     */
    public function userStatusIsValid($email, $confirmAccountMode);
    
    /**
     * Sets the mail handler that will be used for operations requiring to send an email to the user.
     * @param Object $mailHandler An instance of mail handler.
     */
    public function setMailHandler($mailHandler);
    
    /**
     * Initializes the database tables if needed. If the data tables exist, this method will exit.
     * @param Bool $overwrite If true, the tables will recreate, even if they exist. Be careful, this will wipe out all pwLessAuth data.
     */
    public function initializePasswordLessAuthDatabase($overwrite);

    /**
     * Gets all user settings for a concrete user.
	 * Optionally, device_id can be specified to retrieve just the settings for that device.
     * @param Int $user_id 		Id of the user.
     */
    public function getUserSettings($user_id);

	/**
     * Gets the user setting for a concrete user_id and a setting name.
     * @param Int $user_id 		Id of the user.
     * @param String $setting 	Name of the setting to retrieve.
     */
    public function getUserSetting($user_id, $setting);

	/**
     * Sets the user setting for a concrete user_id and a setting name.
	 * If the setting exists, it will overwrite it. Otherwise, the setting will be created.
     * @param Int $user_id 		Id of the user.
     * @param String $setting 	Name of the setting to retrieve.
     */
    public function setUserSetting($user_id, $setting, $value);

	/**
     * Deletes the user setting for a concrete user_id and a setting name, if exists.
     * @param Int $user_id 		Id of the user.
     * @param String $setting 	Name of the setting to retrieve.
     */
    public function delUserSetting($user_id, $setting);

}

?>
