<?php
/**
 * Tests to check that the database functionality is working.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
require_once __DIR__ . '/../vendor/autoload.php'; // Autoload files using Composer autoload

use PasswordLessAuth\Database\Mysql\MySQLDbHandler;

$dbName = 'testpwless';
$dbUsername = 'root';
$dbPassword = 'cambiame';
$dbHost = '127.0.0.1';

$dbHandler = new MySQLDbHandler($dbHost, $dbUsername, $dbPassword, $dbName);
$email = "contact@digitalleaves.com";
echo "User $email exists? " . ($dbHandler->userExists($email) ? "yay!" : "nope") . "\n";

?>
