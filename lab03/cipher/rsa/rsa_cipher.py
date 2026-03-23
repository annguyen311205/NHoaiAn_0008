import rsa
import os

KEY_PATH = 'cipher/rsa/keys'
if not os.path.exists(KEY_PATH):
    os.makedirs(KEY_PATH)

class RSACipher:
    def __init__(self):
        pass

    def generate_keys(self):
        # Tạo cặp khóa 1024 bits
        (public_key, private_key) = rsa.newkeys(1024)
        
        # Lưu Public Key
        with open(f'{KEY_PATH}/publicKey.pem', 'wb') as p:
            p.write(public_key.save_pkcs1('PEM'))
            
        # Lưu Private Key
        with open(f'{KEY_PATH}/privateKey.pem', 'wb') as p:
            p.write(private_key.save_pkcs1('PEM'))

    def load_keys(self):
        # Đọc khóa từ file
        with open(f'{KEY_PATH}/publicKey.pem', 'rb') as p:
            public_key = rsa.PublicKey.load_pkcs1(p.read())
        with open(f'{KEY_PATH}/privateKey.pem', 'rb') as p:
            private_key = rsa.PrivateKey.load_pkcs1(p.read())
        return private_key, public_key

    def encrypt(self, message, key):
        # Dùng utf-8 thay vì ascii để hỗ trợ tiếng Việt
        return rsa.encrypt(message.encode('utf-8'), key)

    def decrypt(self, ciphertext, key):
        try:
            return rsa.decrypt(ciphertext, key).decode('utf-8')
        except Exception as e:
            print(f"Decrypt Error: {e}")
            return False

    def sign(self, message, key):
        # Tạo chữ ký số với thuật toán SHA-1
        return rsa.sign(message.encode('utf-8'), key, 'SHA-1')

    def verify(self, message, signature, key):
        try:
            # rsa.verify trả về phương thức băm (ví dụ 'SHA-1') nếu thành công
            # Nếu thất bại sẽ văng lỗi VerificationError
            return rsa.verify(message.encode('utf-8'), signature, key) == 'SHA-1'
        except Exception as e:
            print(f"Verify Error: {e}")
            return False