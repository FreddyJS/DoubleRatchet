import time
import ratchet

import paho.mqtt.client as mqtt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend

ROOT_KEY = b'>\xe0+\xd7\x97]\x1e4\xb1\xca\xc6\xa3\x07\xba]\x1c'
CHAIN_KEY = None

KEY_PAIR = ratchet.generate_dh()
PEER_KEY = None

MQTT_BROKER = 'broker.hivemq.com'
MQTT_PORT = 1883


def print_green(text: str):
    # Get the current time in [HH:MM:SS] format
    time_str = time.strftime('[%H:%M:%S]', time.localtime())

    # Print the time in white, followed by the text in green
    print(f'\033[97m{time_str} \033[92m{text}\033[0m')


def mqtt_on_message(client: mqtt.Client, userdata: dict, msg: mqtt.MQTTMessage):
    global ROOT_KEY, CHAIN_KEY, PEER_KEY

    public_key = msg.payload.split(b'\n-----END PUBLIC KEY-----')[0] + b'\n-----END PUBLIC KEY-----'
    if PEER_KEY != public_key:
        # New peer key
        dhpublic_key: dh.DHPublicKey = serialization.load_pem_public_key(public_key, backend=default_backend())
        dh_output = ratchet.dh_output(KEY_PAIR, dhpublic_key)

        ROOT_KEY, CHAIN_KEY = ratchet.kdf_rk(ROOT_KEY, dh_output)
        PEER_KEY = public_key

    if len(msg.payload) == len(public_key):
        return

    CHAIN_KEY, message_key = ratchet.kdf_ck(CHAIN_KEY)
    cypertext = msg.payload.split(b'\n-----END PUBLIC KEY-----')[1]
    try:
        plaintext = ratchet.decrypt(cypertext, message_key, b'AES-256-CBC')
        print_green(plaintext.decode())
    except Exception as e:
        print('Failed to decrypt message')
        print('ERROR: ' + str(e) + '\n')


def mqtt_on_connect(client: mqtt.Client, userdata: dict, flags, rc):
    client.subscribe('tor.in')


mqtt_client = mqtt.Client('tor_client')
mqtt_client.on_message = mqtt_on_message
mqtt_client.on_connect = mqtt_on_connect
mqtt_client.connect(host=MQTT_BROKER, port=MQTT_PORT)
mqtt_client.loop_start()

while not mqtt_client.is_connected():
    time.sleep(0.1)


# Send the public key to the peer
mqtt_client.publish('tor.out', KEY_PAIR.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).strip())
while PEER_KEY is None:
    time.sleep(0.1)

print()
print_green('Welcome to the Tor chat server! Type "exit" to quit.')
while True:
    message = input('')
    if message == 'exit':
        break

    CHAIN_KEY, message_key = ratchet.kdf_ck(CHAIN_KEY)
    cypertext = ratchet.encrypt(message.encode(), message_key, b'AES-256-CBC')
    header = KEY_PAIR.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).strip()

    mqtt_message = header + cypertext
    mqtt_client.publish('tor.out', mqtt_message)
    time.sleep(0.25)
