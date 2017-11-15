<?php
/**
 * Tests to check that the encryption functionality is working.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload

$keyType = "rsa";
$keyLength = 2048;
$privateKey = __DIR__.'/private.key';
$publicKey = __DIR__.'/public.key';
$certificate = __DIR__.'/certificate.pem';

echo "Public key file located at ".$publicKey."\n";
echo "Private key file located at ".$privateKey."\n";
echo "Certificate file located at ".$certificate."\n";


use PasswordLessAuth\Encryption\EncryptionConfiguration;
use PasswordLessAuth\Encryption\EncryptionHandler;

// generate configs
$publicConfig = EncryptionConfiguration::publicServerConfiguration($publicKey, $certificate, $keyType, $keyLength);
$privateConfig = EncryptionConfiguration::privateServerConfiguration($privateKey, $keyType, $keyLength);
print("Public config: ".var_export($publicConfig, true)."\n");
print("Private config: ".var_export($privateConfig, true)."\n");

// generate encryption handlers
$privateCriptor = new EncryptionHandler($privateConfig);
$publicCriptor = new EncryptionHandler($publicConfig);
print("Public criptor: ".var_export($publicCriptor, true)."\n");
print("Private criptor: ".var_export($publicCriptor, true)."\n");

// test public key
$publicKeyValid = $publicCriptor->checkPublicKeyIsValid();
echo "Public key valid: ".($publicKeyValid ? "yes!" : "no, sorry...")."\n";

// encript/decript

$plainText = "La lluvia en Sevilla es una pura maravilla...";
print("Plain text: ".$plainText."\n");
$ciphered = $publicCriptor->encrypt_message($plainText);
print("Ciphered message: ".$ciphered."\n");
$deciphered = $privateCriptor->decrypt_message($ciphered);
print("Deciphered message: ".$deciphered."\n");

// sign/verify

$token = "s78ovn4p98ravnefpa8anu3cpw8vb";
print("Initial token to sign: ".$token."\n");
$signature = $privateCriptor->sign_message($token);
print("Signature: ".$signature."\n");
$signatureValid = $publicCriptor->validate_signature($token, $signature);
print("Signature valid? ".($signatureValid ? "yes!" : "no, sorry...")."\n");

echo("\nEncryption tests finished...\n");
    
?>