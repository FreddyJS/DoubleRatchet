from cryptography.hazmat.primitives.asymmetric import dh


ROOT_KEY = b'>\xe0+\xd7\x97]\x1e4\xb1\xca\xc6\xa3\x07\xba]\x1c'
KEYS = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()
KEYS2 = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()

print("KEYS:", KEYS.private_bytes())
print()
print("KEYS2:", KEYS2.private_bytes())

shared_key = KEYS.exchange(KEYS2.public_key())
shared_key2 = KEYS2.exchange(KEYS.public_key())

print(shared_key == shared_key2)
