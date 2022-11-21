from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
from cryptography.hazmat.primitives.hashes import SHA256

ROOT_KEY = b'>\xe0+\xd7\x97]\x1e4\xb1\xca\xc6\xa3\x07\xba]\x1c'

RATCHET_KEY_LENGTH = 80
RATCHET_KEY_INFO = b'This are some arbitrary bytes'

RATCHET_IV_LENGTH = 12
RATCHET_KEY_LENGTH = 32


def ratchet_key(key_pair: dh.DHPrivateKey, pub_key: dh.DHPublicKey) -> bytes:
    shared_key = key_pair.exchange(pub_key)

    keys = HKDF(
        algorithm=SHA256(),
        length=RATCHET_KEY_LENGTH,
        salt=b''*RATCHET_KEY_LENGTH,
        info=RATCHET_KEY_INFO
    ).derive(shared_key)

    return keys[:RATCHET_KEY_LENGTH], keys[RATCHET_KEY_LENGTH:RATCHET_KEY_LENGTH*2], keys[RATCHET_KEY_LENGTH*2:]


# Derive new keys using  the root key
def derive_keys(root_key: bytes) -> bytes:
    keys = HKDF(
        algorithm=SHA256(),
        length=RATCHET_KEY_LENGTH,
        salt=b''*RATCHET_KEY_LENGTH,
        info=RATCHET_KEY_INFO
    ).derive(root_key)

    return keys[:RATCHET_KEY_LENGTH], keys[RATCHET_KEY_LENGTH:RATCHET_KEY_LENGTH*2], keys[RATCHET_KEY_LENGTH*2:]

server_keys = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()
client_keys = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()

public_key = server_keys.public_key().public_bytes(
    encoding=Encoding.PEM,
    format=PublicFormat.SubjectPublicKeyInfo
)
private_key = server_keys.private_bytes(
    encoding=Encoding.PEM,
    format=PrivateFormat.PKCS8,
    encryption_algorithm=NoEncryption()
)

print("Server Public key: \n{}\n".format(public_key))
print("Server Private key: \n{}\n".format(private_key))

# Server sends public key to client
sended_server_public_key = server_keys.public_key()

# Client receives public key from server and generates shared key
client_derived_key = ratchet_key(
    client_keys,
    sended_server_public_key
)

server_derived_key = ratchet_key(
    server_keys,
    client_keys.public_key()
)

assert client_derived_key == server_derived_key, "Keys are not equal"

# Server sends a 'Hello World' message to client
message = b'Hello World'

ciphertext = AESGCM(server_derived_key[0:32]).encrypt(
    nonce=None,
    data=message,
    associated_data=None
)

# Client receives message from server
plaintext = AESGCM(client_derived_key[0:32]).decrypt(
    nonce=None,
    data=ciphertext,
    associated_data=None
)

print("Message: {}".format(plaintext))
