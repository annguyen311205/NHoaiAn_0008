import sys
import os
from PyQt5.QtWidgets import QApplication, QMainWindow, QMessageBox
from ui.rsa import Ui_MainWindow
import requests


class MyApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.ui = Ui_MainWindow()
        self.ui.setupUi(self)

        # Kết nối các nút bấm với hàm xử lý
        self.ui.btn_gen_keys.clicked.connect(self.call_api_gen_keys)
        self.ui.btn_encrypt.clicked.connect(self.call_api_encrypt)
        self.ui.btn_decrypt.clicked.connect(self.call_api_decrypt)
        self.ui.btn_sign.clicked.connect(self.call_api_sign)
        self.ui.btn_verify.clicked.connect(self.call_api_verify)

    def show_error(self, title, message):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Critical)
        msg.setWindowTitle(title)
        msg.setText(message)
        msg.exec_()

    def show_info(self, message):
        msg = QMessageBox()
        msg.setIcon(QMessageBox.Information)
        msg.setWindowTitle("Thông báo")
        msg.setText(message)
        msg.exec_()

    def call_api_gen_keys(self):
        url = "http://127.0.0.1:5000/api/rsa/generate_keys"
        try:
            response = requests.get(url)
            if response.status_code == 200:
                data = response.json()
                self.show_info(data.get("message", "Đã tạo khóa thành công!"))
            else:
                self.show_error("Lỗi API", f"Mã lỗi: {response.status_code}")
        except Exception as e:
            self.show_error("Lỗi kết nối", str(e))

    def call_api_encrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/encrypt"
        payload = {
            "message": self.ui.txt_plain_text.toPlainText(),
            "key_type": "public"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_cipher_text.setPlainText(data.get("encrypted_message", ""))
                self.show_info("Mã hóa thành công!")
            else:
                self.show_error("Lỗi API", "Vui lòng nhấn 'Generate Keys' trước khi mã hóa.")
        except Exception as e:
            self.show_error("Lỗi kết nối", str(e))

    def call_api_decrypt(self):
        url = "http://127.0.0.1:5000/api/rsa/decrypt"
        payload = {
            "ciphertext": self.ui.txt_cipher_text.toPlainText(),
            "key_type": "private"
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_plain_text.setPlainText(data.get("decrypted_message", ""))
                self.show_info("Giải mã thành công!")
            else:
                self.show_error("Lỗi API", "Không thể giải mã bản tin này.")
        except Exception as e:
            self.show_error("Lỗi kết nối", str(e))

    def call_api_sign(self):
        url = "http://127.0.0.1:5000/api/rsa/sign"
        payload = {
            "message": self.ui.txt_info.toPlainText()
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                self.ui.txt_sign.setPlainText(data.get("signature", ""))
                self.show_info("Đã ký văn bản thành công!")
            else:
                self.show_error("Lỗi API", "Lỗi khi tạo chữ ký số.")
        except Exception as e:
            self.show_error("Lỗi kết nối", str(e))

    def call_api_verify(self):
        url = "http://127.0.0.1:5000/api/rsa/verify"
        payload = {
            "message": self.ui.txt_info.toPlainText(),
            "signature": self.ui.txt_sign.toPlainText()
        }
        try:
            response = requests.post(url, json=payload)
            if response.status_code == 200:
                data = response.json()
                if data.get("is_verified", False):
                    self.show_info("Xác thực thành công: Chữ ký hợp lệ!")
                else:
                    self.show_error("Xác thực thất bại", "Chữ ký không hợp lệ hoặc văn bản đã bị sửa đổi.")
            else:
                self.show_error("Lỗi API", "Lỗi khi xác thực chữ ký.")
        except Exception as e:
            self.show_error("Lỗi kết nối", str(e))

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MyApp()
    window.show()
    sys.exit(app.exec_())