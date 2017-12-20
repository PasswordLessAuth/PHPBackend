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
     * @param String $keyData              User public key of the private-public key pair.
     * @param String $keyType              Type of public key (one of PWLESS_KEY_TYPE_*.
     * @param String $keyLength            Length of public key (256, 384, 1024, 2048, 4096...).
     * @param String $deviceInfo           A string identifying the device.
     * @param String $signatureAlgorithm   Signature algorithm used by the device.
     * @param String $mustConfirmEmail   	True if the user status should be set to 0 so the user needs to confirm their email.
     */
    public function registerUser($email, $keyData, $keyType, $keyLength, $deviceInfo, $signatureAlgorithm, $mustConfirmEmail);

    /**
     * Creates a new user, and associated device and key entry with the given public key data.
     * @param String $email 	            User email
     * @param String $keyData              User public key of the private-public key pair.
     * @param String $keyType              Type of public key (one of PWLESS_KEY_TYPE_*.
     * @param String $keyLength            Length of public key (256, 384, 1024, 2048, 4096...).
     * @param String $deviceInfo           A string identifying the device.
     * @param String $signatureAlgorithm   Signature algorithm used by the device.
     * @param String $securityCode         Security code to validate the addition of the device to the user's account.
     */
    public function addDeviceToUser($email, $keyData, $keyType, $keyLength, $deviceInfo, $signatureAlgorithm, $securityCode);

    /**
	 * Deletes the device and associated key for the user. Requires the security code.
     * Updates the user's security code. Returns the code on a successful operation, or false if an error happened.
     * @param String $email 	            User email
     * @param String $keyId                ID of the key to delete.
     * @param String $securityCode         Security code to validate the deletion of the device in the user's account.
     */
    public function deleteUserDeviceAndKeyEntry($email, $keyId, $securityCode);

    /**
     * Deletes a key entry from the devices and key table.
     * @param String $keyId                ID of the key to delete.
     * @param String $userId               ID of the user associated to this device/key entry.
     */
    public function deleteKeyEntry($keyId, $userId);

	/**
	 * Generates a login request for the given user if it exists and its valid.
     * @param String $email 			User email
     * @param String $securityNonce		A plain text security nonce to be signed by the server.
	 * @return the login token for the user to sign and send a /login_validate request.
	 */
	public function generateLoginRequest($email, $keyId);

    /**
     * Validates the user login after a login request.
     * @param String $email 	      	User email
     * @param String $loginSignature 	The login key signature returned by the user to the login request.
     * @returns mixed an associative array with the user's data if the login validation succeed, false otherwise
     */
    public function validateLogin($email, $keyId, $loginTokenSigned);

    /**
     * Checking for user by email address
     * @param String $email email to check in db
     * @return boolean
     */
    public function userExists($email);

    /**
     * Fetching user data by email
     * @param String $email                     User email
     * @param Bool   $includeKeyInformation   If true, all public key information will also be retrieved.
     */
    public function getUserByEmail($email, $includeKeyInformation = false);

    /**
     * Fetching user data by email
     * @param String $email                     User email
     * @param Bool   $includeKeyInformation   If true, all public key information will also be retrieved.
     */
    public function getUserById($userId, $includeKeyInformation = false);

    /**
     * Fetching the devices and keys for a user
     * @param String $userId user id primary key in user table
     * @returns array The access token for that user and that key id.
     */
    public function getKeysForUserWithId($userId);

    /**
     * Gets the key information from concrete device of a concrete user with a email and key_id. Do not use this method
     * to return information to the user, as it outputs private data.
     * @param Int $email    user email
     * @param Int $keyId   key id primary key in user table
     * @returns an associative array containing the key information..
     */
    public function getFullKeyInformationForUserWithEmail($email, $keyId);
    
    /**
     * Gets the key information from concrete device of a concrete user with a user_id and key_id. Do not use this method
     * to return information to the user, as it outputs private data.
     * @param Int $userId  user id primary key in user table
     * @param Int $keyId   key id primary key in user table
     * @returns an associative array containing the key information..
     */
    public function getFullKeyInformationForUserWithId($userId, $keyId);

    /**
     * Fetching user api key
     * @param String $userId user id primary key in user table
     * @param String $keyId  key id primary key in user table
     * @returns String The access token for that user and that key id.
     */
    public function getAccessTokenById($userId, $keyId);

    /**
     * Fetching user id by access token
     * @param String $accessToken user access token
     */
    public function getUserIdForAccessToken($accessToken);

    /**
     * Validates a user API key and returns the ID of the user if it's valid, false otherwise.
	 * AN API key will validate if it's valid for a user with status = confirmed or status = unconfirmed created less than a week ago.
     * @param String $accessToken user api key
     * @return array An array with the id (0) and key (1) of the user if API key was valid, false otherwise.
     */
    public function userIdAndDeviceKeyForAccessToken($accessToken);

    /**
	 * Generates a new login token, associates it with the user and returns it if successful.
	 * @param String $email	email of the user
	 * @returns the newly generated login token or false if it couldn't be generated and inserted in the database.
	 */
	public function newLoginKeyForUserKeyEntry($userId, $keyId);

	/**
	 * Sets the status of a user identified with an id to a given value.
	 * @param Int $userId	ID of the user
	 * @param Int $status 	new status to set.
	 */
	public function setUserStatus($userId, $status);

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
     * @param Int $userId 		Id of the user.
     */
    public function getUserSettings($userId);

	/**
     * Gets the user setting for a concrete user_id and a setting name.
     * @param Int $userId 		Id of the user.
     * @param String $setting 	Name of the setting to retrieve.
     */
    public function getUserSetting($userId, $setting);

	/**
     * Sets the user setting for a concrete user_id and a setting name.
	 * If the setting exists, it will overwrite it. Otherwise, the setting will be created.
     * @param Int $userId 		Id of the user.
     * @param String $setting 	Name of the setting to retrieve.
     */
    public function setUserSetting($userId, $setting, $value);

	/**
     * Deletes the user setting for a concrete user_id and a setting name, if exists.
     * @param Int $userId 		Id of the user.
     * @param String $setting 	Name of the setting to retrieve.
     */
    public function delUserSetting($userId, $setting);

    /**
     * Retrieves the security code for a user with certain ID
     * @param Int userId    The ID of the user to retrieve the security code from.
     */
    public function securityCodeForUserWithId($userId);
    /**
     * Retrieves the security code for a user with certain email
     * @param String email    The email of the user to retrieve the security code from.
     */
    public function securityCodeForUserWithEmail($email);

    /**
     * Checks the security code for a user with certain email.
     * @param String email    The email of the user to check the security code.
	 * @return Bool true if the code is correct, false otherwise.
     */
    public function checkSecurityCodeForUserWithEmail($email, $code);

    /**
     * Checks the security code for a user with certain ID.
     * @param String email    The email of the user to check the security code.
	 * @return Bool true if the code is correct, false otherwise.
     */
    public function checkSecurityCodeForUserWithId($userId, $code);

	/**
	 * Logs the user out. Should replace the access token in the database with a random value that's guaranteed
	 * not to allow any user to authenticate using it (i.e: don't validates user/key/hash checks).
     * @param Int $userId 		Id of the user.
     * @param Int $keyId 		Id of the device/key pair.
	 */
	public function logoutUser($userId, $keyId);

	/**
	 * Delete the user account. Must delete all information from a user, including user data, devices and settings.
	 * The PasswordLessManager hook should allow APIs to delete user data from their databases too.
	 * Requires secure code confirmation.
     * @param Int $userId 		Id of the user.
	 */
	public function deleteUserAccount($userId, $securityCode);
}

?>
