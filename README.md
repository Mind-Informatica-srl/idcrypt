# Shared secret encryption/decryption engine

This module implement a shared secret encryption/description engine that can be
used to successfully encrypt data that should be readable by different actors.

## Prerequisites

- Go 1.14 of newer

## Security of the engine

This system is secure as the passwords choosen by users are. Password are stored
using a PBKDF2 scheme using HMAC-SHA-1 hash.