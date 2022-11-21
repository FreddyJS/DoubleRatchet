from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA256

ROOT_KEY = b'>\xe0+\xd7\x97]\x1e4\xb1\xca\xc6\xa3\x07\xba]\x1c'
KEYS = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()
# KEYS2 = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()

RATCHET_KEY_LENGTH = 80
RATCHET_KEY_INFO = b'This are some arbitrary bytes'

RATCHET_IV_LENGTH = 12

print("KEYS:", KEYS.private_bytes(encoding=Encoding.PEM,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption()))
print()
# print("KEYS2:", KEYS2.private_bytes(encoding=Encoding.PEM,
#     format=PrivateFormat.PKCS8,
#     encryption_algorithm=NoEncryption()))

# shared_key = KEYS.exchange(KEYS2.public_key())
# shared_key2 = KEYS2.exchange(KEYS.public_key())

# print(shared_key == shared_key2)


material_key=KEYS.exchange(KEYS.public_key())

def derive_keys(material_key: bytes) -> bytes:
    keys = HKDF(
        algorithm=SHA256(),
        length=RATCHET_KEY_LENGTH,
        salt=b''*RATCHET_KEY_LENGTH,
        info=RATCHET_KEY_INFO
    ).derive(material_key)
    print(keys)
    print(len(keys))
    return keys[:32], keys[32:64], keys[64:]


key_encrypt,key_auth,key_iv=derive_keys(material_key)
print()
print(key_encrypt)