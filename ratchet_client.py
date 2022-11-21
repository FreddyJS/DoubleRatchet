from cryptography.hazmat.primitives.asymmetric import dh


ROOT_KEY = b'>\xe0+\xd7\x97]\x1e4\xb1\xca\xc6\xa3\x07\xba]\x1c'
KEYS = dh.generate_parameters(generator=2, key_size=2048).generate_private_key()
