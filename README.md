# project3
# JWKS Server Security Enhancement

## Overview

This project enhances a JWKS server by adding AES encryption for private keys, user registration, authentication logging, and rate limiting.

## Setup

Install dependencies:
pip install flask argon2-cffi cryptography

Set environment variable:

Windows:
$env:NOT_MY_KEY="your_secret_key"

Mac/Linux:
export NOT_MY_KEY="your_secret_key"

Run server:
python app.py

## Endpoints

POST /register
Registers a user and returns a generated password.

POST /auth
Authenticates user and logs request.

## Security Features

* AES encryption for private keys
* Argon2 password hashing
* Environment variable key management
* Authentication logging
* Rate limiting (10 requests/sec)


* Passwords are securely hashed
* Encryption key is never exposed
