import dh_parameters

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.hmac import HMAC


DH_PARAMETERS = dh.DHParameterNumbers(dh_parameters.P, dh_parameters.G).parameters(default_backend())
DERIVED_KEY_LENGTH = 80
INFO = b'handshake'
TAG_LENGTH = 32


def generate_dh():
    return DH_PARAMETERS.generate_private_key()


def dh_output(private_key: dh.DHPrivateKey, public_key: dh.DHPublicKey) -> bytes:
    return private_key.exchange(public_key)


def kdf_rk(rk: bytes, dh_output: bytes) -> bytes:
    result = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=INFO,
    ).derive(rk + dh_output)

    return result[:16], result[16:]


def kdf_ck(ck: bytes) -> bytes:
    result = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=b'\x00' * 32,
        info=INFO,
    ).derive(ck)

    return result[:16], result[16:]


def derive(key, info):
    derived_key = HKDF(
        algorithm=SHA256(),
        length=DERIVED_KEY_LENGTH,
        salt=b'\x00' * DERIVED_KEY_LENGTH,
        info=info,
    ).derive(key)

    return derived_key[:32], derived_key[32:64], derived_key[64:]


def hmac(key: bytes, data: bytes) -> bytes:
    hmac = HMAC(key, SHA256(), backend=default_backend())
    hmac.update(data)
    return hmac.finalize()


def aes_cbc_encrypt(key: bytes, iv: bytes, plaintext: bytes):
    padder = PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    aes = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).encryptor()

    return aes.update(padded_plaintext) + aes.finalize()


def aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    aes = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    ).decryptor()

    padded_plaintext = aes.update(ciphertext) + aes.finalize()

    unpadder = PKCS7(128).unpadder()
    return unpadder.update(padded_plaintext) + unpadder.finalize()


def encrypt(plaintext: bytes, key: bytes, associated_data: bytes) -> bytes:
    # Get the derived keys
    encryption_key, authentication_key, iv = derive(key, INFO)

    # Encrypt the plaintext using AES-CBC with PKCS7 padding
    ciphertext = aes_cbc_encrypt(encryption_key, iv, plaintext)

    # Calculate the authentication tag
    tag = hmac(authentication_key, associated_data + ciphertext)

    # Return the ciphertext and the tag
    return ciphertext + tag


def decrypt(ciphertext: bytes, key: bytes, associated_data: bytes) -> bytes:
    # Get the derived keys
    decryption_key, authentication_key, iv = derive(key, INFO)

    # Split the authentication tag from the ciphertext
    tag = ciphertext[-TAG_LENGTH:]
    ciphertext = ciphertext[:-TAG_LENGTH]

    # Verify the authentication tag
    calculated_tag = hmac(authentication_key, associated_data + ciphertext)
    if tag != calculated_tag:
        raise Exception(f'Invalid tag! Expected {tag.hex()}, got {calculated_tag.hex()}')

    # Decrypt the ciphertext using AES-CBC with PKCS7 padding
    return aes_cbc_decrypt(decryption_key, iv, ciphertext)
