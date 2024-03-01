# CurvyStreamCrypt

## Overview
CurvyStreamCrypt is a hybrid encryption system that combines my BLAKE3-based StreamCrypt stream cipher with elliptic curve cryptography (ECC) using the `brainpoolP256r1` curve. Designed for end-to-end encryption, it provides a secure and efficient method for encrypting and decrypting messages.

## Features
- Utilizes BLAKE3 for fast and secure key derivation in the stream cipher component.
- Employs elliptic curve cryptography (ECC) on the `brainpoolP256r1` curve for generating private and public keys, ensuring robust asymmetric encryption.
- Offers point compression and key derivation functionalities, enhancing efficiency in key storage and exchange.
- Designed for secure end-to-end encryption, making it suitable for confidential communications.

## Requirements
- Python 3.6 or above
- NumMaster
- TinyEC
- NumPy

## Installation
To use CurvyStreamCrypt, ensure you have Python installed on your system. Then, install the required Python packages using pip:

```bash
pip install nummaster tinyec numpy
```

## Usage

### Key Generation
Generate a private key and its corresponding public key:

```python
from CurvyStreamCrypt import create_private_key, create_public_key

privKey = create_private_key()
pubKey = create_public_key(privKey)
```

### Encrypting a Message
Encrypt a message using the public key:

```python
encrypted_msg = encrypt(b'Your message here', pubKey)
```

### Decrypting a Message
Decrypt the message using the private key:

```python
decrypted_msg = decrypt(encrypted_msg, privKey)
```

## Example
Here's a quick example demonstrating how to encrypt and decrypt a message:

```python
privKey = create_private_key()
pubKey = create_public_key(privKey)

emsg = encrypt(b'Hello, World!', pubKey)
print(f'Encrypted Message: {emsg}')

dmsg = decrypt(emsg, privKey)
print(f'Decrypted Message: {dmsg}')
```

## Security Notes
- Always keep your private keys secure and never share them.
- Ensure secure storage and handling of all cryptographic material.