<?php
/**
 * Main configuration file with constants and common variables.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */

/******* Constants *********/

/**
 * Server key pair and key types.
 */
define ('PWLESS_KEY_TYPE_RSA', "rsa");   // key in RSA format
define ('PWLESS_KEY_TYPE_EC', "ec");    // key in EC format (curve 256cp1)
define ('PWLESS_KEY_TYPE_PUBLIC', 'public');
define ('PWLESS_KEY_TYPE_PRIVATE', 'private');

define ('PWLESS_AUTHENTICATION_MODE_STRICT', 'strict');
define ('PWLESS_AUTHENTICATION_MODE_LAX', 'lax');

/**
 * Account statuses
 **/
define ('PWLESS_ACCOUNT_UNCONFIRMED', 0);
define ('PWLESS_ACCOUNT_CONFIRMED', 1);
define ('PWLESS_ACCOUNT_DISABLED', 2);

/**
 * API parameters
 **/
define ('PWLESS_API_PARAM_EMAIL', 'email');
define ('PWLESS_API_PARAM_KEY', 'key');
define ('PWLESS_API_PARAM_PUBLIC_KEY', 'public_key');
define ('PWLESS_API_PARAM_SEC_NONCE', 'security_nonce');
define ('PWLESS_API_PARAM_DEVICE_INFO', 'device_info');
define ('PWLESS_API_PARAM_SUCCESS', 'success');
define ('PWLESS_API_PARAM_ERROR', 'error');
define ('PWLESS_API_PARAM_KEY_ID', 'key_id');
define ('PWLESS_API_PARAM_SEC_NONCE_SIGNED', 'security_nonce_signed');
define ('PWLESS_API_PARAM_CODE', 'code');
define ('PWLESS_API_PARAM_LOGIN_TOKEN', 'login_token');
define ('PWLESS_API_PARAM_LOGIN_TOKEN_SIGNED', 'login_token_signed');
define ('PWLESS_API_PARAM_AUTH', 'auth');
define ('PWLESS_API_PARAM_ACCESS_TOKEN', 'access_token');
define ('PWLESS_API_PARAM_EXPIRES', 'expires');
define ('PWLESS_API_PARAM_NEXT_LOGIN_TOKEN', 'next_login_token');
define ('PWLESS_API_PARAM_SECURITY_CODE', 'security_code');
define ('PWLESS_API_PARAM_SETTINGS', 'settings');
define ('PWLESS_API_PARAM_KEY_TYPES', 'key_types');
define ('PWLESS_API_PARAM_AUTHENTICATION_MODE', 'authentication_mode');
define ('PWLESS_API_PARAM_ACCEPTED_KEYS', 'accepted_keys');
define ('PWLESS_API_PARAM_ACCEPTS_NONCE', 'accepts_nonce');
define ('PWLESS_API_PARAM_DEVICES', 'devices');
define ('PWLESS_API_PARAM_USER', 'user');
define ('PWLESS_API_PARAM_ID', 'id');
define ('PWLESS_API_PARAM_KEY_TYPE', 'key_type');
define ('PWLESS_API_PARAM_KEY_LENGTH', 'key_length');
define ('PWLESS_API_PARAM_REGISTERED', 'registered');
define ('PWLESS_API_PARAM_LAST_LOGIN', 'last_login');
define ('PWLESS_API_PARAM_MESSAGE', 'message');
define ('PWLESS_API_PARAM_KEYS', 'keys');
define ('PWLESS_API_PARAM_CREATED_AT', 'created_at');
define ('PWLESS_API_PARAM_STATUS', 'status');
define ('PWLESS_API_PARAM_KEY_DATA', 'key_data');
define ('PWLESS_API_PARAM_SIGNATURE_ALGORITHM', 'signature_algorithm');
define ('PWLESS_API_PARAM_USER_ID', 'user_id');
define ('PWLESS_API_PARAM_CERTIFICATE', 'certificate');

/**
 * Error codes
 **/
define ('PWLESS_ERROR_CODE_SUCCESS', "success");
define ('PWLESS_ERROR_CODE_UNDEFINED_ERROR', "undefined_error");
define ('PWLESS_ERROR_CODE_BAD_REQUEST', "bad_request");
define ('PWLESS_ERROR_CODE_UNABLE_REGISTER_USER', "unable_register_user");
define ('PWLESS_ERROR_CODE_MISSING_OR_EMPTY_PARAMETERS', "missing_parameters");
define ('PWLESS_ERROR_CODE_MALFORMED_EMAIL_ADDRESS', "malformed_email");
define ('PWLESS_ERROR_CODE_IDENTITY_VALIDATION_FAILED', "identity_validation_failed");
define ('PWLESS_ERROR_CODE_UNABLE_RETRIEVE_DATA', "unable_retrieve_data");
define ('PWLESS_ERROR_CODE_ACCOUNT_NEEDS_ACTIVATION', "account_not_active");
define ('PWLESS_ERROR_CODE_UNABLE_SEND_MAIL', "unable_send_email");
define ('PWLESS_ERROR_CODE_CODE_VALIDATION_REQUIRED', "code_validation_required");
define ('PWLESS_ERROR_CODE_INVALID_KEY', "invalid_key");
define ('PWLESS_ERROR_CODE_INVALID_SECURITY_CODE', "invalid_security_code");
define ('PWLESS_ERROR_CODE_NETWORK_ERROR', "network_error");

/**
 * PwLessAuth options
 **/
define ('PWLESS_OPTION_RECREATE_PWLESS_DATABASE', 'recreate_pwless_database');


/**
 * Global constants
 */
define ('PWLESS_UNCONFIRMED_ACCOUNT_USE_TIME', 604800); // 1 week time (in seconds).
define ('PWLESS_LOGIN_REQUEST_VALIDITY_TIME', 3600); // 1 week time (in seconds).
define ('PWLESS_SECURITY_CODE_LENGTH', 8);
define ('PWLESS_TOKEN_RANDOM_BYTES_LENGTH', 40);
define ('PWLESS_WEEK_IN_SECONDS', 7*24*60*60);
define ('PWLESS_SECURITY_CODE_FILENAME', 'security_code.html');
define ('PWLESS_CONFIRM_ACCOUNT_FILENAME', 'confirm_account.html');

/**
 * Endpoints
 */
define ('PWLESS_ENDPOINT_CONFIRM_ACCOUNT', "/pwless/confirm");

/**
 * Passwordless configuration and settings
 */
define ('PWLESS_SETTING_CONFIRM_ACCOUNT_MODE', "confirm_account_mode");
define ('PWLESS_SETTING_USE_SECURITY_NONCE', "use_security_nonce");
define ('PWLESS_SETTING_AUTHENTICATION_MODE', "authentication_mode");
define ('PWLESS_SETTING_ACCEPTED_KEYS', "accepted_keys");
define ('PWLESS_SETTING_MAIL_CONFIGURATION', "mail_configuration");

define ('PWLESS_CONFIRMATION_EMAIL_NONE', "none");       // Users are not required to confirm their emails before using their account
define ('PWLESS_CONFIRMATION_EMAIL_LAX', "lax");        // Users are required to confirm their emails up to one week after registering their accounts
define ('PWLESS_CONFIRMATION_EMAIL_STRICT', "strict");     // Users are required to confirm their emails immediately to use their accounts

?>
