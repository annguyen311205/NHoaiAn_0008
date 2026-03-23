import ecdsa
import os

if not os.path.exists('cipher/ecc/keys'):
    os.makedirs('cipher/ecc/keys')

class ECCCipher:
    def __init__(self):
        pass
    
    def generate_keys(self):
        sk = ecdsa.SigningKey.generate() # Tạo khóa bí mật (Private Key)
        vk = sk.get_verifying_key()      # Lấy khóa công khai (Public Key)
        
        with open('cipher/ecc/keys/privateKey.pem', 'wb') as f:
            f.write(sk.to_pem())
        with open('cipher/ecc/keys/publicKey.pem', 'wb') as f:
            f.write(vk.to_pem())

    def load_keys(self):
        with open('cipher/ecc/keys/privateKey.pem', 'rb') as f:
            sk = ecdsa.SigningKey.from_pem(f.read())
        with open('cipher/ecc/keys/publicKey.pem', 'rb') as f:
            vk = ecdsa.VerifyingKey.from_pem(f.read())
        return sk, vk

    def sign(self, message, key):
        # Ký dữ liệu bằng khóa riêng tư
        return key.sign(message.encode('ascii'))

    def verify(self, message, signature, key):
        try:
            return key.verify(signature, message.encode('ascii'))
        except ecdsa.BadSignatureError:
            return False