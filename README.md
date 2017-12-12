# PasswordLessAuth PHP framework

This package contains the [PasswordLessAuth](https://passwordlessauth.com) backend implementation for PHP, using Slim 3.X.

PasswordLessAuth is an open source authentication paradigm relying on strong cryptography and biometric sensors to allow developers to include secure, real password-less authentication to their applications.

This project contains the backend implementation for a XAMP system (LAMP, MAMP and even WAMP), relying on PHP (>= 5.3) and MySQL.

## Install

### Composer

The best way to install the PasswordLessAuth PHP backend is via [Composer](https://getcomposer.org/).

Create a directory that will hold your project and install PasswordLessAuth via composer:

```
$ mkdir /path/to/pwlesstest
$ cd /path/to/pwlesstest
$ composer require digitalleaves/passwordlessauth
```

If you have not worked with Composer before, here is an [starting guide](https://getcomposer.org/doc/00-intro.md) to help you get started.

Composer will create a vendor directory and some composer files:

```
$ ls -l
total 32
drwxr-xr-x   5 User  staff    160 Dec 11 17:33 .
drwxr-xr-x@ 67 User  staff   2144 Dec 11 17:15 ..
-rw-r--r--   1 User  staff     76 Dec 11 17:32 composer.json
-rw-r--r--   1 User  staff  12156 Dec 11 17:33 composer.lock
drwxr-xr-x  10 User  staff    320 Dec 11 17:33 vendor
```

### Manually

Although not recommended, you can download the source code from the [Github repository](https://github.com/PasswordLessAuth/PHPBackend) and install it locally.

In that case, you will have to take care of the dependencies and autoload to load your classes.

## Getting Started Guide

The PHP version of PasswordLessAuth uses PHP (Version >= 5.3.0) and MySQL (>= 5.5.0). You will need a Web server too, and the ability to rewrite or redirect calls to a RESTful manager. 

We will use Apache2 in the examples and use the mod_rewrite module, but you can deploy this example on a NginX Web server.

### Running The Demo Locally

There's a sample backend index.php file to allow you to run a demo locally. In order to do that, follow these simple steps:

#### Install and configure a XAMP system.

If you are on Mac OS X, you can install [Bitnami's MAMP](https://bitnami.com/stack/mamp/installer). Bitnami also has a [WAMP package](https://bitnami.com/stack/wamp/installer) for Windows users (yikes!).

Follow the instructions on the install package for an initial setup & configuration.

On Linux, simply install apache2, php5 or above, and mysql. Depending on your distro, it can be done in a single command, for instance, for Debian-like distributions:

`# apt-get update && apt-get install apache2 mysql-server php5 php-pear php5-mysql`

If you are a Linux user, you actually know how to do this, right? 😉

#### Configure The Database

You should add a database and a user for PasswordLessAuth. If you plan on using the demo as is, the configuration should be:

* database name: testpwless
* database user: testpwless
* password: testpwless
* host: localhost
  
If you are on MAMP or WAMP, you can easily do this via PHPMyAdmin. On linux, you can also use the mysql command.

Test that you can access the database locally with your username and password "testpwless". If you choose different credentials, you will have to change them later in the index.php file.

#### Create a Fake Local Virtual Host

Let's create a fake virtual host to test the PasswordLessAuth backend. Open your web server configuration file. If you are using MAMP or WAMP you can do that by selecting **Manage Servers > Apache Web Server > Configure > Open Conf File**.

Now add this line just below the \<Directory\>...\</Directory\> entry:

```
# PasswordLessAuth PHP library test fake VHost.
<VirtualHost *:8080>
    ServerName pwlesstest.com
    ServerAdmin webmaster@localhost
    DocumentRoot /path/to/pwlesstest/vendor/digitalleaves/passwordlessauth/tests/backendTests

    <Directory /path/to/pwlesstest/vendor/digitalleaves/passwordlessauth/tests/backendTests>
        Options -Indexes +FollowSymLinks +MultiViews
        AllowOverride All
        Order allow,deny
        allow from all
    </Directory>
</VirtualHost>
```

*Replace /path/to/pwlesstest/vendor/digitalleaves/passwordlessauth/tests/backendTests with the path to your PasswordLessAuth test directory.*

#### Add Fake Entry in /etc/hosts

Now we will add a fake DNS entry at /etc/hosts pointing to our local server. Edit /etc/hosts (in Windows, this file is on *c:\WINDOWS\system32\drivers\etc\hosts*). Add the following entry at the bottom of the file:

```
127.0.0.1	pwlesstest.com

```

Now open a browser, point it to pwlesstest.com:8080/ and you should get a success JSON response.

![PasswordLessAuth PHP backend demo running](http://passwordlessauth.com/images/doc/pwlesstest.png)

🎉 Congratulations! Your local demo server is ready to be used.

## Authenticated and Non Authenticated Endpoints

Now that you have your demo environment up and running, let's try some things. The GET / is an unauthenticated endpoint that can be called without authentication. Let's now try an authenticated endpoint, like GET /helloworld. Point your browser to:

```
http://pwlesstest.com:8080/helloworld
```

You will get a 401 "unauthorized" response:

```
401 Unauthorized
{"success":false,"message":"Access Denied. Invalid access token or unconfirmed user account."}
```

Thus, we need to log in and get an access token to use these authenticated endpoints. In order to do that, we will first need to sign up to get a valid account.

## Signing up

Let's sign up our first user. In order to do that, you will need a RESTful client like [Postman](https://www.getpostman.com/) or a good old terminal with the WGET command.

The signup flow is explained in depth [here](http://passwordlessauth.com/signup_flow.html).

For these examples, I will be using Postman.

We also need to generate a pair of public and private keys for our user. I will illustrate the process in Linux or macOS using *OpenSSL*. If you are on Windows, you should generate and check a private and public keys yourself.

First, we will generate the RSA (2048 bits) private key. In order to do that, open a terminal and type:

```
$ openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048
```

Now, we will create the corresponding public key:

```
$ openssl rsa -pubout -in private_key.pem -out public_key.pem
```

You can check that both keys have been properly generated with these commands:

```
$ openssl rsa -text -in private_key.pem
$ openssl rsa -text -pubin -in public_key.pem
```

Check that you can print the public key: you will need it for the signup request:

```
$ cat public_key.pem
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5a38tqYfWxP1N97k7Eo
GESQ2nilRe743XcZDwWyHkyM2MuImxBNLA6PxktMvLiWUS1AyMDH6BUuVZ8i8exq
0MNHcKQPJf0eFbUuiV9cuZss4gp0TGnmjwHTIstogLjjgmQe0PzsM370JDZ2Sk0x
P1okOOYJucjio/ih6S49sDYQVstt+ewsQ6RvAJoLVcoHolVuitK2yISQeVl27niR
/A/lQ7n2TU3ZcFMiewQGSJaum3Vv2LzhF1VBpmmUYV0oNc6vpmu7JlKcpCmIGKUg
p2WIhkcInmHJGD6vCUG0QhKv7MqKW3aAoqj4JcodsJMxjkvCG46N3eUOLLRyg8Yh
lQIDAQAB
-----END PUBLIC KEY-----
```

Next, we are ready to perform our registration request. We will perform a POST request to http://pwlesstest.com:8080/pwless/signup. Set the body to raw JSON (application/JSON), as the image below shows:

![PasswordLessAuth PHP Backend demo. Signing up.](http://passwordlessauth.com/images/doc/signup.png)

This will be the request:

```
{
	"email": "user@email.com",
	"key_data": "-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5a38tqYfWxP1N97k7Eo
GESQ2nilRe743XcZDwWyHkyM2MuImxBNLA6PxktMvLiWUS1AyMDH6BUuVZ8i8exq
0MNHcKQPJf0eFbUuiV9cuZss4gp0TGnmjwHTIstogLjjgmQe0PzsM370JDZ2Sk0x
P1okOOYJucjio/ih6S49sDYQVstt+ewsQ6RvAJoLVcoHolVuitK2yISQeVl27niR
/A/lQ7n2TU3ZcFMiewQGSJaum3Vv2LzhF1VBpmmUYV0oNc6vpmu7JlKcpCmIGKUg
p2WIhkcInmHJGD6vCUG0QhKv7MqKW3aAoqj4JcodsJMxjkvCG46N3eUOLLRyg8Yh
lQIDAQAB
-----END PUBLIC KEY-----",
	"key_length": 2048,
	"key_type": "rsa",
	"signature_algorithm": "SHA1"

}
```

You should replace "user@email.com" with a proper email of yours.

The response should be something like this:

```
{
    "success": true,
    "code": "success",
    "message": "You are successfully registered",
    "user": {
        "id": 1,
        "email": "user@email.com",
        "key": {
            "id": 1,
            "key_type": "rsa",
            "signature_algorithm": "SHA1",
            "key_length": 2048,
            "device_info": "Unknown device",
            "key_data": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt5a38tqYfWxP1N97k7Eo\nGESQ2nilRe743XcZDwWyHkyM2MuImxBNLA6PxktMvLiWUS1AyMDH6BUuVZ8i8exq\n0MNHcKQPJf0eFbUuiV9cuZss4gp0TGnmjwHTIstogLjjgmQe0PzsM370JDZ2Sk0x\nP1okOOYJucjio/ih6S49sDYQVstt+ewsQ6RvAJoLVcoHolVuitK2yISQeVl27niR\n/A/lQ7n2TU3ZcFMiewQGSJaum3Vv2LzhF1VBpmmUYV0oNc6vpmu7JlKcpCmIGKUg\np2WIhkcInmHJGD6vCUG0QhKv7MqKW3aAoqj4JcodsJMxjkvCG46N3eUOLLRyg8Yh\nlQIDAQAB\n-----END PUBLIC KEY-----"
        }
    }
}
```

😎 Cool! So we are registered now. Now we can initiate the login process:

## Login In

The login process is composed of two parts, a [Login flow](http://passwordlessauth.com/login_flow.html) and an [Access Token flow](http://passwordlessauth.com/access_token_flow.html).

### Login Request

To initiate the Login flow, we will perform a POST request, this time to http://pwlesstest:8080/pwless/login. 

This should be the body of the request:

```
{
	"email": "user@email.com",
	"key_id": 1,
	"security_nonce": "5738929837423"
}
```

Again, replace the email address with your own email address. Upon receiving this request, the server will do three things:

* Check that the email is valid, and corresponds to a registered user that has a registered device key with that key_id.
* Sign the security nonce so the user can verify the backend's identity
* Return a login token to the user, which is a cryptographic challenge. The user should sign it with the private key and send it back to the backend to verify its identity.

Thus, our response would look similar to this:

```
{
    "success": true,
    "code": "success",
    "login_token": "ImreFOPaQNm0oEPzrZtZ0dEUBUUXfvmaAg3WpDooFLQvA8eOzAllpg==",
    "security_nonce_signed": "PwG2VX7AlhN57aTHRPU12lte0upz..."
}
```

Our client now has to:

* Verify the signature contained in security_nonce_signed
* Sign and send back the login_token
* Get the response with the access token

### Verifying the Backend's Signature

The file *verify_server_signature.sh* at the tests/backendTests directory allows you to verify the received *security\_nonce\_signed*. Basically it does a signature using OpenSSL.

```
$ openssl dgst -sha1 -verify password_server_key.pem -signature signature.txt plain.txt  

```

Just save the unsigned security_token you sent into a file called *plain.txt*. Make sure you don't add a newline `0x0A` character at the end. Then, save the received *security\_nonce\_signed* in a file called *signature.txt*, taking care of not adding newlines characters also.

```
$ echo -n "5738929837423" > plain.txt
$ hexdump -C plain.txt 
00000000  35 37 33 38 39 32 39 38  33 37 34 32 33           |5738929837423|
0000000d

$ echo -n "PwG2VX7AlhN57aTHRPU1..." > signature.txt
$ hexdump -C signature.txt 
00000000  50 77 47 32 56 58 37 41  6c 68 4e 35 37 61 54 48  |PwG2VX7AlhN57aTH|
00000010  52 50 55 31 32 6c 74 65  30 75 70 7a 5a 7a 58 73  |RPU12lte0upzZzXs|
00000020  34 42 34 69 74 53 65 41  54 57 77 58 77 45 54 4f  |4B4itSeATWwXwETO|
...
00000130  78 71 48 6a 47 74 47 2f  57 54 36 5a 4b 61 49 55  |xqHjGtG/WT6ZKaIU|
00000140  6d 37 65 37 42 34 66 73  55 73 38 31 4b 4b 4c 47  |m7e7B4fsUs81KKLG|
00000150  71 76 41 51 72 77 3d 3d                           |qvAQrw==|
00000158
```

Then, save the server's public key into a file called backend_server_key.pem and just run:

```
$ ./verify_server_signature.sh
Verification Ok
```

Ok, so we can trust our server. Now time to authenticate ourselves by signing the *login_key* that the server sent us.

### Getting an Access Token

To sign the *login_token*, we can use the script *sign_login_token.sh* from *tests/backendTests*. It basically generates a digest of the login_token (contained in a file called "login_token.txt" without newlines), codifies it in base64 and signs it.

```
openssl dgst -sha1 -sign private_key.pem -out login_token_signed.sha1 login_token.txt 
openssl base64 -in login_token_signed.sha1 -out login_token_signed.txt
cat login_token_signed.txt | tr -d "\n"
echo
```

Running it with our *login_token* will give us the *login_token_signed*:

```
$ ./sign_login_token.sh 
MIqB2d+1/eyOGVk9k+69DCEIC1ltdaeTPiY1oG5GuG/I...V3GxvrEndSy1toXbyFoDmA==
```

Now we can do a POST request to *http://pwlesstest.com:8080/pwless/access* and get the access token:

```
POST http://pwlesstest.com:8080/pwless/access
{
	"email": "user@email.com",
	"key_id": 1,
	"login_token_signed": "MIqB2d+1/eyOGVk9k+69DCEIC1ltdaeTPiY1...V3GxvrEndSy1toXbyFoDmA=="
}
```

If everything goes well, the response should be:

```
Response: 200 OK
{
   "success": true,
   "code": "success",
   "user": { "id": 1, "email": "user@email.com" },
   "key": { "id": 1, "key_type": "rsa", "key_length": 2048, ... },
   "auth": {
      "access_token": "1_1goYKypIQApJ1BJUPF7E6qMJSdK...3oe/o6vQ==",
      "expires": "2016-04-21T11:35:21.000Z",
      "next_login_token": "ImoeFOPaQMn0oEPzrZ...QvA8eOzAllpg"
   }
}
```

Congratulations! 🎉 You have successfully logged in. Now you can perform authenticated requests. Let's see one of them.

## Performing Authenticated Requests

Now let's repeat our /helloworld request, but now with an access token. The authenticated requests should pass the access token in an "Authorization" header, without any tag (like Bearer or similar in OAuth tokens).

```
GET /helloworld HTTP/1.1
Host: pwlesstest.com:8080
Authorization: 1_1goYKypIQApJ1BJUP...l2j3oe/o6vQ==
Cache-Control: no-cache
Postman-Token: 8809377b-ae2e-28bd-6b76-3847a61dce79
```

And this would be the response:

```
{
    "success": true,
    "message": "Hello world! You are authenticated!"
}
```

## What's Next

Now that you have your PasswordLessAuth backend ready to authenticate and serve users, you might want to test it with different clients (like mobile iOS or Android clients) and expand it with new endpoints.

### Available Clients

The previous demo used a RESTful client (Postman or Wget via the command line) as a way of illustrating how to get started with the backend and check everything's correctly configured.

However, there are libraries and frameworks ready to be used with PasswordLessAuth, and more being built, for iOS, Android, and plain Javascript.

Please, check [PasswordLessAuth](https://passwordlessauth.com) website or the [Project's Github repository](https://github.com/PasswordLessAuth) for more information.

### User Guide.

To read a complete documentation, please refer to the Wiki.

### About PasswordLessAuth

PasswordLessAuth wants to offer a better solution for developers than OAuth, currently the de-facto standard for Social Login today.

To begin with, OAuth is not a real authentication system. It does not provide authentication, but authorization.

This difference is important. With OAuth, you can affirm that someone has authorized your application to access some data from an authentication service in the past, but you haven't actually authenticated the user. The authentication of the user depends on a third party company (like Facebook), and you have no control on how strict this authentication is, or if a real authentication is enforced once the user has already signed in before.

This also means that, at most, OAuth will give you a pair of tokens from a third party service. What you do with them is not specified in the protocol. Thus, the most important part of the authentication process is undetermined, and left to the developer (sometimes resulting in poor authentication practices).

Additionally, OAuth is hard to understand by developers. It's a complicated and certainly outdated protocol. I have worked with OAuth extensively throughout the years, so this is a justified statement. Not a single developer will tell you that they had a great time implementing or integrating OAuth in their apps.

Furthermore, OAuth is terrible for the user experience within modern mobile applications. The authorization of the user happens in a browser window. On many Android and iOS Apps, that means switching to the browser or opening a browser within your application, completely ruining the user experience.

Finally, for some developers, leaving the authentication of your users to third party companies like Facebook, Google or Twitter poses some important security and privacy concerns.

## License

Copyright 2017 Ignacio Nieto Carvajal (<contact@passwordlessauth.com>).

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

