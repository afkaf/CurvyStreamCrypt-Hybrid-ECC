from nummaster.basic import sqrtmod
from tinyec import registry
from tinyec.ec import Point
import numpy as np
import secrets
import blake3

curve = registry.get_curve('brainpoolP256r1')
context = 'StreamCrypt-2db12ea77123cf47d288753b12914f61102d92a8b3a2d220c65e80a99004f3a7-by-afkaf'


# STREAMCRYPT ENCRYPTION STUFF
# Stream Cipher Encryption using BLAKE3 for key derivation and encryption. Salts are used in place of nonce.
def encrypt_sc(data, keyword):
    salt = secrets.token_bytes(64)  # salt generation
    initial_key = blake3.blake3(keyword + salt, derive_key_context=context).digest(length=64)  # Hash password and salt
    keystream = blake3.blake3(initial_key, derive_key_context=context).digest(length=len(data))
    data_array = np.frombuffer(data, dtype=np.uint8)
    keystream_array = np.frombuffer(keystream, dtype=np.uint8)
    secret = np.bitwise_xor(data_array, keystream_array).tobytes()
    return salt + secret  # Prepend salt to secret for decryption

def decrypt_sc(secret, keyword):
    salt, encrypted_data = secret[:64], secret[64:]  # Extract salt and encrypted data
    initial_key = blake3.blake3(keyword + salt, derive_key_context=context).digest(length=64)  # Recreate initial key
    keystream = blake3.blake3(initial_key, derive_key_context=context).digest(length=len(encrypted_data))
    encrypted_array = np.frombuffer(encrypted_data, dtype=np.uint8)
    keystream_array = np.frombuffer(keystream, dtype=np.uint8)
    data = np.bitwise_xor(encrypted_array, keystream_array).tobytes()
    return data


# ECC ENCRYPTION STUFF
# Elliptic Curve Cryptography (ECC) layer for asymmetric encryption. Uses ECC for key exchange and BLAKE3 for deriving a shared key.
def encrypt_ecc(msg, public_key):
    ciphertext_private_key = secrets.randbelow(curve.field.n)
    shared_ecc_key = ciphertext_private_key * public_key
    secretKey = ecc_point_to_256_bit_key(shared_ecc_key)
    ciphertext = encrypt_sc(msg, secretKey)
    ciphertext_public_key = ciphertext_private_key * curve.g
    return (ciphertext, ciphertext_public_key)

def decrypt_ecc(encrypted_msg, private_key):
    (ciphertext, ciphertext_public_key) = encrypted_msg
    shared_ecc_key = private_key * ciphertext_public_key
    secretKey = ecc_point_to_256_bit_key(shared_ecc_key)
    plaintext = decrypt_sc(ciphertext, secretKey)
    return plaintext


# POINT COMPRESSION AND KEY DERIVATION
# Functions for converting ECC points into a format usable for encryption keys and compressing/decompressing ECC public keys for storage.
def ecc_point_to_256_bit_key(point):
    point_bytes = int.to_bytes(point.x, 32, 'big') + int.to_bytes(point.y, 32, 'big')
    return blake3.blake3(point_bytes, derive_key_context=context).digest()

def compress_point(point):
    return hex(point.x) + hex(point.y % 2)[2:]

def decompress_to_point(curve, compressed_key):
    x, is_odd = compressed_key[0:-1], compressed_key[-1]
    p, a, b = curve.g.p, curve.a, curve.b
    x = int(x,16)
    is_odd = int(is_odd)
    y = sqrtmod(pow(x, 3, p) + a * x + b, p)
    if bool(is_odd) == bool(y & 1):
        return Point(curve, x, y)
    return Point(curve,x, p - y)


#  MAIN ENCRYPT/DECRYPT
#  High-level encryption/decryption and key creation interface.
def create_private_key():
    return secrets.randbelow(curve.field.n)

def create_public_key(private_key):
    return private_key * curve.g

def decrypt(encrypted_msg, private_key):
    encrypted_msg = encrypted_msg.split(',')
    encrypted_msg = [bytes.fromhex(encrypted_msg[0])] + [decompress_to_point(curve,encrypted_msg[1])]
    return decrypt_ecc(encrypted_msg, private_key)

def encrypt(msg, public_key):
    encrypted_msg = encrypt_ecc(msg, public_key)
    encrypted_msg = [encrypted_msg[0].hex()] + [compress_point(encrypted_msg[1])]
    return ','.join(encrypted_msg)
