<?php
/**
 * Global test to setup a complete PasswordLessAuth backend.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 * 
 * Steps to use this test:
 * i. create a local mySQL database. Either use the credentials used in section 2 below or change that values.
 * ii. create an entry in your local apache2 installation pointing to this directory, with a virtual host
 *     like pwlesstest.com:8080. Make sure to allow override for .htaccess.
 * iii. edit your /etc/hosts file to add an entry for pwlesstest.com pointing to 127.0.0.1
 * iv. send and include the public key to your clients for server identity verification.
 * v. start the apache2 + mySQL servers. Test http://pwlesstest.com:8080/pwless/info or http://pwlesstest.com:8080/.
 * Then, test an authenticated endpoint like http://pwlesstest.com:8080/helloworld
 */

require_once __DIR__ . '/../../vendor/autoload.php'; // Autoload files using Composer autoload

error_log(__DIR__ . '/../../vendor/autoload.php');

// Dependencies
use PasswordLessAuth\Encryption\ServerEncryptionEnvironment;
use PasswordLessAuth\Database\Mysql\MySQLDbHandler;
use PasswordLessAuth\PasswordLessManager;

// 1. Create and load the certificate, public and private keys and build a server encryption environment
$publicKey = __DIR__.'/public.key';
$privateKey = __DIR__.'/private.key';
$certificate = __DIR__.'/certificate.pem';
$serverEncryptionEnvironment = new ServerEncryptionEnvironment($privateKey, $publicKey, $certificate, "rsa", 2048);

// 2. Database
$dbName = 'testpwless';
$dbUsername = 'testpwless';
$dbPassword = 'testpwless';
$dbHost = '127.0.0.1';

$dbHandler = new MySQLDbHandler($dbHost, $dbUsername, $dbPassword, $dbName);

// 3. Routing app: Slim.
$routeApp = new \Slim\App();

// 4. We can now build a PasswordLessAuth backend.
$pwLessManager = new PasswordLessManager($routeApp, $dbHandler, $serverEncryptionEnvironment);

// 5. Define some authenticated and not authenticated routes
$routeApp->get('/', function ($req, $res, $args) {
    $data = array();
    $data["success"] = true;
    $res->withHeader('Content-type', 'application/json')->withStatus(200)->write(json_encode($data));
});

$routeApp->get('/helloworld', function ($req, $res, $args) {
    $data = array();
    $data["success"] = true;
    $data["message"] = "Hello world! You are authenticated!";
    $res->withHeader('Content-type', 'application/json')->withStatus(200)->write(json_encode($data));
})->add([$pwLessManager, 'authenticate']);

// Add a hook so we know when someone is asking for the PWLESS_FLOW_PWLESSINFO flow.
try {
	$pwLessManager->setHookForFlow(PasswordLessManager::PWLESS_FLOW_PWLESSINFO, function ($success, $data) {
		error_log("PwLessAuth server info flow executed. Result: " . $success . ". Data: ");
		error_log(var_export($data, true));
	});
} catch (Exception $e) {
	error_log("An error happened while trying to set the hook for the PWLESS_FLOW_PWLESSINFO flow. ".$e);
}

// Now run the routing app!
$routeApp->run();

?>
