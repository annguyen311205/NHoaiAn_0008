from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import struct

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 12345))

print("Connected to server!")

# Generate RSA key
client_key = RSA.generate(2048)

def recv_full(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

# Receive server public key
server_public_key = RSA.import_key(client_socket.recv(2048))

# Send client public key
client_socket.send(client_key.publickey().export_key(format="PEM"))

# Receive encrypted AES key
encrypted_aes_key = recv_full(client_socket, 256)

# Decrypt AES key
aes_cipher = PKCS1_OAEP.new(client_key)
aes_key = aes_cipher.decrypt(encrypted_aes_key)

print("Secure AES key established!")

# Encrypt message
def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + ciphertext

# Decrypt message
def decrypt_message(key, message):
    iv = message[:AES.block_size]
    encrypted_message = message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(encrypted_message), AES.block_size)
    return decrypted_message.decode()

# Receive messages
def receive_messages():
    while True:
        try:
            raw_len = recv_full(client_socket, 4)
            if not raw_len:
                break

            msg_len = struct.unpack("!I", raw_len)[0]
            encrypted_message = recv_full(client_socket, msg_len)

            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print("\nReceived:", decrypted_message)

        except:
            break

# Start receiving thread
thread = threading.Thread(target=receive_messages, daemon=True)
thread.start()

# Send messages
while True:
    message = input("Enter message ('exit' to quit): ")

    encrypted_message = encrypt_message(aes_key, message)

    client_socket.sendall(struct.pack("!I", len(encrypted_message)))
    client_socket.sendall(encrypted_message)

    if message == "exit":
        break

client_socket.close()