<?php
/**
 * Tests to check if a client key is valid.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload

use PasswordLessAuth\Encryption\EncryptionConfiguration;
use PasswordLessAuth\Encryption\EncryptionHandler;

$keyData = "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA6UQNSh72ey9KQ4OEP3VF
aJHe9f6mouj83L8xDC3FYexWbBhnU/nZLUFVokZRua/u2crLeXc92JAev6xGhFct
/bPcKmH5eDQMCbL/nu0eVcQSz6fbSrWE+H6OFibj534X8v7dE6dgJm/jvxWV1dfR
w+RhCPr1EUM4f8+d1v5zTj1oXpDIwZq54DLRy2lCyS8YDzwBWQw471wICfVn1w8k
8EMmKz5B26ZjfEjgXRtgFJDQKlun2HZhNmmIVkgpNvplX+d98yawBYZGkweTuMHx
+gR03N5ZTrSm3bZ69+CXHjyIpFEc0oyw1pOhufb9jypd0CaF2OAYUpRZnWgX0rh6
6wIDAQAB
-----END PUBLIC KEY-----";
$keyType = "rsa";
$keyLength = 2048;

$config = new EncryptionConfiguration($keyData, $keyType, $keyLength, $signatureAlgorithm, PWLESS_KEY_TYPE_PUBLIC);
$eh = new EncryptionHandler($config);
echo "Testing public key:\n" . $keyData . "\n";
$keyValid = $eh->checkPublicKeyIsValid();
echo "key is " . ($keyValid ? "valid" : "invalid") . "\n";

?>
