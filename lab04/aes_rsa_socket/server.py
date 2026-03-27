from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import socket
import threading
import struct

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 12345))
server_socket.listen(5)

print("Server is running on port 12345...")

server_key = RSA.generate(2048)

clients = []

def recv_full(sock, n):
    data = b''
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data += packet
    return data

def encrypt_message(key, message):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(message.encode(), AES.block_size))
    return cipher.iv + cipher_text
def decrypt_message(key, encrypted_message):
    iv = encrypted_message[:AES.block_size]
    cipher_text = encrypted_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = unpad(cipher.decrypt(cipher_text), AES.block_size)
    return decrypted_message.decode()

def handle_client(client_socket, client_address):
    print(f"Connected with {client_address}")

    client_socket.send(server_key.publickey().export_key(format='PEM'))

    client_received_key = RSA.import_key(client_socket.recv(2048))

    aes_key = get_random_bytes(16)

    cipher_rsa = PKCS1_OAEP.new(client_received_key)
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)
    client_socket.send(encrypted_aes_key)

    clients.append((client_socket, aes_key))

    while True:
        try:
            raw_len = recv_full(client_socket, 4)
            if not raw_len:
                break

            msg_len = struct.unpack("!I", raw_len)[0]
            encrypted_message = recv_full(client_socket, msg_len)

            decrypted_message = decrypt_message(aes_key, encrypted_message)
            print(f"[{client_address}] {decrypted_message}")

            for sock, key in clients:
                encrypted = encrypt_message(key, decrypted_message)
                sock.sendall(struct.pack("!I", len(encrypted)))
                sock.sendall(encrypted)

            if decrypted_message == "exit":
                break

        except:
            break

    clients.remove((client_socket, aes_key))
    client_socket.close()
    print("Client disconnected:", client_address)

while True:
    client_socket, client_address = server_socket.accept()
    thread = threading.Thread(
        target=handle_client,
        args=(client_socket, client_address),
        daemon=True
    )
    thread.start()