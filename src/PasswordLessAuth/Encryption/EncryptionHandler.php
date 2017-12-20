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
			$keyRef = openssl_get_publickey($this->config->keyData);
			$success = openssl_public_encrypt($message, $encrypted, $keyRef);
			openssl_free_key($keyRef);
		}
		else if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PRIVATE) {
			$keyRef = openssl_get_privatekey($this->config->keyData);
			$success = openssl_private_encrypt($message, $encrypted, $keyRef);
			openssl_free_key($keyRef);
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
			$keyRef = openssl_get_publickey($this->config->keyData);
			$success = openssl_public_decrypt($data, $decrypted, $keyRef);
			openssl_free_key($keyRef);
		}
		else if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PRIVATE) {
			$keyRef = openssl_get_privatekey($this->config->keyData);
			$success = openssl_private_decrypt($data, $decrypted, $keyRef);
			openssl_free_key($keyRef);
		}

		// analyze results
		if ($success) { return $decrypted; }
		else { return false; }
	}

	public function sign_message($message, $wrapInBase64 = true) {
		if ($this->config->publicOrPrivate == PWLESS_KEY_TYPE_PUBLIC) { return false; }
		else {
			if ($keyData = $this->config->keyData) {
				$status = openssl_sign($message, $signature, $keyData, $this->config->signatureAlgorithm);
				if ($status == false) { return false; }
				else if ($wrapInBase64) { return base64_encode($signature); }
				else { return $signature; }
			} else { return false; }
		}
	}

	public function validate_signature($base64encodedData, $base64encodedSignature) {
		$signature = base64_decode($base64encodedSignature);
		$keyData = openssl_get_publickey($this->config->keyData);
		$result = openssl_verify($base64encodedData, $signature, $keyData, $this->config->signatureAlgorithm);
		if ($result == 1) { return true; } else { return false; }
	}

	public static function generate_random_token($prefix = null) {
        $randomString = base64_encode(openssl_random_pseudo_bytes(PWLESS_TOKEN_RANDOM_BYTES_LENGTH));
        if ($prefix !== null) { return "{$prefix}" . "." . $randomString; }
		else { return $randomString; }
	}

	public static function generate_cryptographic_token($userId, $keyId) {
		$randomString = base64_encode(openssl_random_pseudo_bytes(PWLESS_TOKEN_CRYPTOGRAPHIC_BYTES_LENGTH));
		$token = $userId . "." . $keyId . "." . strval(time() + PWLESS_TOKEN_EXPIRATION_TIME_IN_SECONDS) . "." . $randomString;
		// append SHA256 hash
		$hash = hash("sha256", $token);
		return $token . "." . $hash;
	}

	public static function cryptographic_token_valid_for($token, $userId, $keyId) {
		// 1. extract the parts
		$parts = explode(".", $token);
		if (count($parts) < 5) { return false; }
		$tokenUserId = $parts[0];
		$tokenKeyId = $parts[1];
		$timeStr = $parts[2];
		$origToken = $tokenUserId . "." . $tokenKeyId . "." . $timeStr . "." . $parts[3];
		$checksum = $parts[4];

		// 2. check user id and key id
		if ($userId != $tokenUserId) { return false; }
		if ($keyId != $tokenKeyId) { return false; }
		// 3. check time
		$time = intval($timeStr);
		if (time() > $time) { return false; }
		// 4. check the hash
		if (hash("sha256", $origToken) != $checksum) { return false; }

		// If everything passed, return true
		return true;
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

    public static function keyConfigurationAllowed($keyType, $keyLength, $signatureAlgorithm) {
        if ($keyType == PWLESS_KEY_TYPE_RSA) {
            if ($keyLength == 2048 || $keyLength == 4096) {
                if ($signatureAlgorithm == "SHA1") { return true; }
            }
        } else if ($keyType == PWLESS_KEY_TYPE_EC) {
            if ($keyLength == 256 && $signatureAlgorithm == "ecdsa-with-SHA1") { return true; }
        }
        return false;
    }
}

?>
