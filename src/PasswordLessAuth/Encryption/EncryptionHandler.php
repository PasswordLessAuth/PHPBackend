<?php

/**
 * Class to handle all encryption/decryption operations.
 * uses public-private asymmetric algorithm cryptography.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Encryption;

require_once (__DIR__.'/../Config/Config.php');

class EncryptionHandler {
    /** The encryption configuration for this encryption handler */
    private $config = null;
    
	/**
	 * The constructor gets a EncryptionConfiguration object.
	 */
	public function __construct($configuration) {
        if (!($configuration instanceof EncryptionConfiguration)) { die("Invalid configuration for PasswordLessAuth EncryptionHandler."); }
        
        $this->config = $configuration;
    }

    /**
     * Verifies that the key information is correct and valid for a public key.
     */
    public function checkPublicKeyIsValid() {
        if (EncryptionHandler::keyConfigurationAllowed($this->config->keyType, $this->config->keyLength, $this->config->signatureAlgorithm)) {
            $keyResource = openssl_get_publickey($this->config->keyData);
            if ($keyResource !== false) { return true; }
        }
        return false;
    }

	/** Encrypts the given message with the public or private key. */
	public function encrypt_message($message, $wrapInBase64 = true) {
		// encrypt.
		$success = false;
		$encrypted = "";
		if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PUBLIC) {
			$key_ref = openssl_get_publickey($this->config->keyData);
			$success = openssl_public_encrypt($message, $encrypted, $key_ref);
			openssl_free_key($key_ref);
		}
		else if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PRIVATE) {
			$key_ref = openssl_get_privatekey($this->config->keyData);
			$success = openssl_private_encrypt($message, $encrypted, $key_ref);
			openssl_free_key($key_ref);
		}

		// analyze results
		if ($success) { return $wrapInBase64 ? base64_encode($encrypted) : $encrypted; }
		else { return false; }
	}

	public function decrypt_message($message, $wrappedInBase64 = true) {
		// decrypt.
		$success = false;
		$decrypted = "";
		$data = $wrappedInBase64 ? base64_decode($message) : $message;

		if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PUBLIC) {
			$key_ref = openssl_get_publickey($this->config->keyData);
			$success = openssl_public_decrypt($data, $decrypted, $key_ref);
			openssl_free_key($key_ref);
		}
		else if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PRIVATE) {
			$key_ref = openssl_get_privatekey($this->config->keyData);
			$success = openssl_private_decrypt($data, $decrypted, $key_ref);
			openssl_free_key($key_ref);
		}

		// analyze results
		if ($success) { return $decrypted; }
		else { return false; }
	}

	public function sign_message($message, $wrapInBase64 = true) {
		if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PUBLIC) { return false; }
		else {
			if ($key_data = $this->config->keyData) {
				$status = openssl_sign($message, $signature, $key_data, $this->config->signatureAlgorithm);
				if ($status == false) { return false; }
				else if ($wrapInBase64) { return base64_encode($signature); }
				else { return $signature; }
			} else { return false; }
		}
	}

	public function validate_signature($base64encoded_data, $base64encoded_signature) {
		$signature = base64_decode($base64encoded_signature);
		$key_data = openssl_get_publickey($this->config->keyData);
		$result = openssl_verify($base64encoded_data, $signature, $key_data, $this->config->signatureAlgorithm);
		if ($result == 1) { return true; } else { return false; }
	}

	public static function generate_token($prefix = null) {
        $randomString = base64_encode(openssl_random_pseudo_bytes(PWLESS_TOKEN_RANDOM_BYTES_LENGTH));
        if ($prefix !== null) { return "{$prefix}" . "_" . $randomString; }
		else { return $randomString; }
	}

    public static function generate_security_code() {
        $lines = file(PWLESS_MOST_COMMON_ENGLISH_WORDS_FILE);
        $word = $lines[array_rand($lines)];
        $word = trim(preg_replace('/\s+/', ' ', $word));
        $length = strlen($word);
        if ($length < PWLESS_SECURITY_CODE_LENGTH) {
            $freeSpace = PWLESS_SECURITY_CODE_LENGTH - $length;
            $number = EncryptionHandler::random_numeric_length($freeSpace);
            return (($number + $length) % 2 == 0) ? $word . $number : $number . $word;
        } else { return substr($word, 0, PWLESS_SECURITY_CODE_LENGTH); }
    }

    public static function random_alphanumeric_length($length) {
        $characters = "abcdefghijklmnopqrstuvwxyzABCDERFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*";
        $randomString = "";
        for ($i = 0; $i < $length; $i++) { $randomString .= $characters[mt_rand(0, strlen($characters)-1)]; }
        return $randomString;
    }

    public static function random_numeric_length($length) {
        $characters = "0123456789";
        $randomString = "";
        for ($i = 0; $i < $length; $i++) { $randomString .= $characters[mt_rand(0, strlen($characters)-1)]; }
        return $randomString;
    }

    public function getServerPublicKeyData() {
		$keyData = array();
        
        // key parameters
        $keyData[PWLESS_API_PARAM_KEY_TYPE] = $this->config->keyType;
        $keyData[PWLESS_API_PARAM_KEY_LENGTH] = $this->config->keyLength;
        $keyData[PWLESS_API_PARAM_SIGNATURE_ALGORITHM] = $this->config->signatureAlgorithm;
        
        // key data
        if (strpos($this->config->keyData, 'file://') === 0 && file_exists($this->config->keyData)) { 
            $keyData[PWLESS_API_PARAM_KEY_DATA] = file_get_contents($this->config->keyData); 
        } else { $keyData[PWLESS_API_PARAM_KEY_DATA] = $this->config->keyData; }
        
        // certificate
        if ($this->config->certificateFileSpecified()) {
            $keyData[PWLESS_API_PARAM_CERTIFICATE] = $this->config->getCertificateData();
        }
        
        return $keyData;
    }

    public static function keyConfigurationAllowed($key_type, $key_length, $signature_algorithm) {
        if ($key_type == PWLESS_KEY_TYPE_RSA) {
            if ($key_length == 2048 || $key_length == 4096) {
                if ($signature_algorithm == "SHA1") { return true; }
            }
        } else if ($key_type == PWLESS_KEY_TYPE_EC) {
            if ($key_length == 256 && $signature_algorithm == "ecdsa-with-SHA1") { return true; }
        }
        return false;
    }
}

?>
