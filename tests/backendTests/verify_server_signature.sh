#!/bin/sh

openssl dgst -sha1 -verify password_server_key.pem -signature signature.txt plain.txt


