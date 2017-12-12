#!/bin/sh
openssl dgst -sha1 -sign private_key.pem -out login_token_signed.sha1 login_token.txt
openssl base64 -in login_token_signed.sha1 -out login_token_signed.txt
cat login_token_signed.txt | tr -d "\n"
echo
