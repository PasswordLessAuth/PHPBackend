<?php

/**
 * DbConnector for mySQL databases.
 *
 * @author Ignacio Nieto Carvajal <contact@passwordlessauth.com>
 * @link URL https://passwordlessauth.com
 */
namespace PasswordLessAuth\Database\Mysql;

class MySQLDbConnect {
    private $dbHost;
    private $dbUsername;
    private $dbPassword;
    private $dbName;
    private $dbPort;
    
    private $conn;

    public function __construct($dbHost, $dbUsername, $dbPassword, $dbName, $dbPort = '3306') {
        $this->dbHost = $dbHost;
        $this->dbUsername = $dbUsername;
        $this->dbPassword = $dbPassword;
        $this->dbName = $dbName;        
        $this->dbPort = $dbPort;        
    }

    /**
     * Establishing database connection
     * @return database connection handler
     */
    function connect() {
        include_once (__DIR__."/../../Config/Config.php");

        // Connecting to mysql database
        $this->conn = new \mysqli($this->dbHost, $this->dbUsername, $this->dbPassword, $this->dbName, $this->dbPort);

        // Check for database connection error
        if (mysqli_connect_errno()) {
            echo "Failed to connect to MySQL: " . mysqli_connect_error();
        }
        // set charset locale to UTF-8
        $this->conn->set_charset("utf8");

        // returing connection resource
        return $this->conn;
    }

}

?>
