<?php

/**
 * This class contains the encryption configuration for the public and private keys of the server/backend.
 * It acts as a container for the two main configurations of the server.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Encryption;

use \PasswordLessAuth\Encryption\EncryptionConfiguration;

require_once(__DIR__."/../Config/Config.php");

class ServerEncryptionEnvironment {
    private $privateKeyConfiguration;
    private $publicKeyConfiguration;
    
    private $privateEncryptionHandler;
    private $publicEncryptionHandler;
    
    public function __construct($serverPrivateKeyFile, $serverPublicKeyFile, $serverCertificateFile, $serverKeyType, $serverKeyLength) {
        $this->publicKeyConfiguration = EncryptionConfiguration::publicServerConfiguration($serverPublicKeyFile, $serverCertificateFile, $serverKeyType, $serverKeyLength, null);
        $this->privateKeyConfiguration = EncryptionConfiguration::privateServerConfiguration($serverPrivateKeyFile, $serverKeyType, $serverKeyLength, null);

        $this->publicEncryptionHandler = new EncryptionHandler($this->publicKeyConfiguration);
        $this->privateEncryptionHandler = new EncryptionHandler($this->privateKeyConfiguration);
    }

    public function getPrivateKeyConfiguration() { return $this->privateKeyConfiguration; }
    public function getPublicKeyConfiguration() { return $this->publicKeyConfiguration; }
    public function getPrivateEncryptionHandler() { return $this->privateEncryptionHandler; }
    public function getPublicEncryptionHandler() { return $this->publicEncryptionHandler; }
}

?>