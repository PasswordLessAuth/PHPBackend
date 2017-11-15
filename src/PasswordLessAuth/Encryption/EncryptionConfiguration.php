<?php

/**
 * Class to store encryption configuration for a server.
 * Includes information about the certificate, public and private keys.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Encryption;

require_once(__DIR__."/../Config/Config.php");

class EncryptionConfiguration {
    /** Key data or key filepath */
    public $keyData = null;
	/** Public or private key */
	public $publicOrPrivate;
    /** Type of key */
    public $keyType = null;
    /** Key length */
    public $keyLength = null;
    /** Digest algorithm */
    public $signatureAlgorithm = null;
    
    // Optional: certificate data.
    private $certificateData = null;

    
    /**
     * Generates a configuration for a client with key data and all the parameters, from the database.
     */
	public function __construct($keyData, $keyType, $keyLength, $signatureAlgorithm = null, $pubOrPriv = PWLESS_KEY_TYPE_PUBLIC) {
		$this->keyData = $keyData;
		$this->publicOrPrivate = $pubOrPriv;
        $this->keyType = $keyType;
        $this->keyLength = $keyLength;
        if ($signatureAlgorithm) { $this->signatureAlgorithm = $signatureAlgorithm; }
        else { $this->signatureAlgorithm = EncryptionConfiguration::digestAlgorithmForKey($keyType, $keyLength); }
    }
    
    public function setCertificateData($certificateFile) {
        $this->certificateData = $certificateFile;
    }
    
    public function certificateFileSpecified() {
        return ($this->certificateData != null);
    }
    
    public function getCertificateData() {
        return $this->certificateData && strpos($this->certificateData, 'file://') === 0 ? file_get_contents($this->certificateData) : $this->certificateData;
    }
    
    static function publicServerConfiguration($keyFile, $certificateFile, $keyType, $keyLength, $digestAlgorithm = null) {
		$config = new EncryptionConfiguration(file_get_contents($keyFile), $keyType, $keyLength, $digestAlgorithm, PWLESS_KEY_TYPE_PUBLIC);
        $config->setCertificateData(file_get_contents($certificateFile));
        return $config;
    }
        
    static function privateServerConfiguration($keyFile, $keyType, $keyLength, $digestAlgorithm = null) {
		return new EncryptionConfiguration(file_get_contents($keyFile), $keyType, $keyLength, $digestAlgorithm, PWLESS_KEY_TYPE_PRIVATE);
    }
    
    static function digestAlgorithmForKey($keyType, $keyLength) {
        if ($keyType == PWLESS_KEY_TYPE_RSA) { return "SHA1"; } 
        else if ($keyType == PWLESS_KEY_TYPE_EC) { return "ecdsa-with-SHA1"; }
        else { return null; }
    }
}

?>