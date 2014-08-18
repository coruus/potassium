# Curve25519-AES256-CTR-HMAC-SHA512

## Howto

An authenticated encryption mode. Works on Pythonista without installing
any additional modules. (Pythonista includes, but does not document,
the PyCrypto module.) To use with Python, do

    pip install -r requirements.txt

To generate a keypair for yourself, do

    write_keypair()

Send `k_curve25519.pub` to whomever you want to message you.

To encrypt a message to a recipient, do

    encrypt(recipient_public_key, 'message')

To decrypt a message encrypted under your public key, using a key saved
in a keyfile, do

    decrypt_withkeyfile(encrypted_message)

The public keys are just plain base64 files.

## Encryption mode summary

Uses elliptic-curve Diffie-Hellman key exchange on djb's Curve25519,
AES-256 in CTR mode, and HMAC-SHA512 over the encrypted message. The
encryption and authentication keys are derived using a random nonce
and the ECDH shared-secret. HMAC-SHA512 is used as the
key-derivation-function.

This provides nonceless deniable encryption. Note that it leaks message
length. This will be changed in a future version; a padding byte is
included, so messages using this version are future-compatible.

The Curve25519 implementation in pure Python is directly adapted from
djb's naclcrypto-20090310 spec.

(The Montgomery ladder routine has been converted to imperative form
to avoid running out of stack-space on some Pythonista builds.)

`encrypt` generates an ephemeral keypair, derives an AES key and an HMAC
key, and encrypts and authenticates a message.
