# Shared secret encryption/decryption engine

This module implement a shared secret encryption/description engine that can be
used to successfully encrypt data that should be readable by different actors.

As a convenience, this module also has a Fecade helping to manage the
2FA authentication devices:

- https://github.com/xlzd/gotp
- https://github.com/skip2/go-qrcode

As a further convenience also a function to transmit a `CredentialRecord` (with
password or not) as a JWT token is provided. This feature is based on the
following library:

- https://github.com/dgrijalva/jwt-go

## Prerequisites

- Go 1.14 of newer

## Security of the engine

This system is secure as the passwords choosen by users are, since the master
key is encrypted using the password of the user.

- Password are stored using a PBKDF2 scheme using HMAC-SHA-1 hash
- Data is encrypted using an AES-256 scheme

## Crypto space definition

A crypto space is composed by:

- as a set of encrypted data
- a set of actors.

Every actor in the crypto space can read the encrypted data. Actors in different
crypto space can't search each other data.

Each crypto space has his own master key, and a master key can be generated
using the function `GenerateMasterKey` in `bitbucket.com/leonardoce/pkg/models`.

The generation of the master key is the first step needed to use this library,
and the generated master key should not be stored in the database.

The master key can be recovered from each credential in the crypto space or
directly in the bootstrap phase.

The master key must not be stored in the database or sent to other servers.

What follows is a set of examples on how a crypto space can be used.

### Creation of a new user

For every credential allowing access to the crypto space a `CredentialRecord`
defined in `bitbucket.com/leonardoce/pkg/models` must be created and stored
persistently.

To create a new user we can use the master key from the bootstrap of the crypto
space, or recover a master key from a user with verified credentials (see the
"Login" section).

To create a new `CredentialRecord` with a master key, you can use the
`NewCredentialRecord` function of `bitbucket.com/leonardoce/pkg/models` with the
first time password. The resulting `CredentialRecord` must the stored in the
persistent data storage.

### Login

Given a `CredentialRecord` we can verify if a password supplied by the user is
good, and if is, we can extract the master key. This can be done via the member
functions of `CredentialRecord`. Look at:

- `IsPasswordValid`
- `RecoverMasterKey`

### Creation of a new session

A new session can be viewed as a new `CredentialRecord` whose username and
passwords are randomly generated and linked to a real user.

The username can be stored in the database, and the password can be sent to the
client, who will send it back to the server for every request together with the
username.

That credential can be than used to recover the master key.

### Encrypting and decrypting data

If you have the master key, you can use it to encrypt or decrypt data. Look at
the following functions in `bitbucket.com/leonardoce/pkg/models`:

- `Encrypt`
- `Decrypt`

Remember that the previous functions don't have any protection against a wrong
key. That means that wrong data will be returned if the master key is not valid.

### Limitations

The encryption and the decryption functions are not time consuming at all, at
least on hardware which directly implements the AES encryption (this is all
modern servers and laptops, too).

The password checking functions are expensive: checking a password takes 8ms on
my laptop. We could evaluate to replace the currently used algorithm with a
faster one, if we want.

## OTP

The facade provided can be used to implement a 2FA authentication scheme. For
every user the TOTP secret must be created and stored.

You can generate a secret using the `CreateRandomSecret` function.

Given a secret, the `NewTOTP` function can be used to bootstrap the engine and,
the first time, a PNG can be generated and shown to the user. Look at the
`GetQRCodeAsPNG` function for that.

When the mobile device is configured, you can check if the password provided by
the user is good using the `Verify` function of the TOTP engine.

The proposed `Makefile` will build a `bin/otp` binary, from `cmd/opt`, which can
be used to test the OTP feature.

Invoking `bin/otp` will produre a `qr.png` file which can be used to configure
the authentiation on a mobile phone App such as Authy.

`bin/otp -check 'codehere'` can be used to check if the OTP proposed by the App
is valid or not.

The code in `cmd/otp/main.go` can be used as a further reference.