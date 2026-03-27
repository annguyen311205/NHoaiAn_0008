import sys
import socket
import struct
import threading

from PyQt5 import uic
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from PyQt5.QtCore import pyqtSignal

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad, unpad


class ChatWindow(QMainWindow):
    message_received = pyqtSignal(str)
    status_changed = pyqtSignal(str, str)

    def __init__(self):
        super().__init__()
        uic.loadUi("chat_client.ui", self)

        self.client_socket = None
        self.client_key = None
        self.aes_key = None
        self.connected = False

        self.disconnectBtn.setEnabled(False)
        self.sendBtn.setEnabled(False)

        self.connectBtn.clicked.connect(self.connect_to_server)
        self.disconnectBtn.clicked.connect(self.disconnect_from_server)
        self.sendBtn.clicked.connect(self.send_message)
        self.messageInput.returnPressed.connect(self.send_message)

        self.message_received.connect(self.append_chat)
        self.status_changed.connect(self.update_status)

    def recv_full(self, sock, n):
        data = b""
        while len(data) < n:
            packet = sock.recv(n - len(data))
            if not packet:
                return None
            data += packet
        return data

    def encrypt_message(self, key, message):
        cipher = AES.new(key, AES.MODE_CBC)
        ciphertext = cipher.encrypt(pad(message.encode("utf-8"), AES.block_size))
        return cipher.iv + ciphertext

    def decrypt_message(self, key, encrypted_data):
        iv = encrypted_data[:AES.block_size]
        ciphertext = encrypted_data[AES.block_size:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
        return plaintext.decode("utf-8")

    def append_chat(self, text):
        self.chatArea.append(text)

    def update_status(self, text, color):
        self.statusLabel.setText(f"Status: {text}")
        self.statusLabel.setStyleSheet(f"color: {color}; font-weight: bold;")

    def connect_to_server(self):
        if self.connected:
            return

        host = self.hostInput.text().strip()
        port_text = self.portInput.text().strip()

        if not host or not port_text:
            QMessageBox.warning(self, "Lỗi", "Vui lòng nhập host và port.")
            return

        try:
            port = int(port_text)
        except ValueError:
            QMessageBox.warning(self, "Lỗi", "Port phải là số.")
            return

        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((host, port))

            self.client_key = RSA.generate(2048)

            server_public_key_data = self.client_socket.recv(2048)
            server_public_key = RSA.import_key(server_public_key_data)

            self.client_socket.send(
                self.client_key.publickey().export_key(format="PEM")
            )

            encrypted_aes_key = self.recv_full(self.client_socket, 256)
            if not encrypted_aes_key:
                raise ConnectionError("Không nhận được AES key từ server.")

            rsa_cipher = PKCS1_OAEP.new(self.client_key)
            self.aes_key = rsa_cipher.decrypt(encrypted_aes_key)

            self.connected = True
            self.status_changed.emit(f"Connected to {host}:{port}", "green")
            self.message_received.emit("[SYSTEM] Connected to server.")
            self.message_received.emit("[SYSTEM] Secure AES key established.")

            self.connectBtn.setEnabled(False)
            self.disconnectBtn.setEnabled(True)
            self.sendBtn.setEnabled(True)

            receive_thread = threading.Thread(
                target=self.receive_messages,
                daemon=True
            )
            receive_thread.start()

        except Exception as e:
            QMessageBox.critical(self, "Lỗi kết nối", str(e))
            self.status_changed.emit("Connection failed", "red")
            if self.client_socket:
                try:
                    self.client_socket.close()
                except Exception:
                    pass
            self.client_socket = None
            self.connected = False

    def receive_messages(self):
        while self.connected:
            try:
                raw_len = self.recv_full(self.client_socket, 4)
                if not raw_len:
                    break

                msg_len = struct.unpack("!I", raw_len)[0]
                encrypted_message = self.recv_full(self.client_socket, msg_len)
                if not encrypted_message:
                    break

                decrypted_message = self.decrypt_message(self.aes_key, encrypted_message)
                self.message_received.emit(f"[RECEIVED] {decrypted_message}")

                if decrypted_message == "exit":
                    break

            except Exception:
                break

        self.handle_disconnect_ui()

    def send_message(self):
        if not self.connected:
            return

        message = self.messageInput.text().strip()
        if not message:
            return

        try:
            encrypted_message = self.encrypt_message(self.aes_key, message)
            self.client_socket.sendall(struct.pack("!I", len(encrypted_message)))
            self.client_socket.sendall(encrypted_message)

            self.message_received.emit(f"[YOU] {message}")
            self.messageInput.clear()

            if message == "exit":
                self.disconnect_from_server()

        except Exception as e:
            QMessageBox.critical(self, "Lỗi gửi tin", str(e))
            self.disconnect_from_server()

    def disconnect_from_server(self):
        if self.client_socket:
            try:
                self.client_socket.close()
            except Exception:
                pass

        self.connected = False
        self.handle_disconnect_ui()

    def handle_disconnect_ui(self):
        self.connected = False
        self.client_socket = None
        self.aes_key = None

        self.connectBtn.setEnabled(True)
        self.disconnectBtn.setEnabled(False)
        self.sendBtn.setEnabled(False)
        self.status_changed.emit("Not connected", "red")
        self.message_received.emit("[SYSTEM] Disconnected.")

    def closeEvent(self, event):
        self.disconnect_from_server()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = ChatWindow()
    window.show()
    sys.exit(app.exec_())