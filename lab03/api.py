from flask import Flask, request, jsonify
from cipher.rsa.rsa_cipher import RSACipher
from cipher.ecc.ecc_cipher import ECCCipher # Import thêm ECC

app = Flask(__name__)

# Khởi tạo logic cho cả hai thuật toán
rsa_logic = RSACipher()
ecc_logic = ECCCipher()

# ================= RSA ROUTES =================

@app.route('/api/rsa/generate_keys', methods=['GET'])
def gen_rsa_keys():
    try:
        rsa_logic.generate_keys()
        return jsonify({'message': 'RSA Keys generated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/encrypt', methods=['POST'])
def rsa_encrypt():
    try:
        data = request.json
        message = data.get('message', '')
        if not message:
            return jsonify({'encrypted_message': ''})
            
        _, pub_key = rsa_logic.load_keys()
        encrypted = rsa_logic.encrypt(message, pub_key)
        return jsonify({'encrypted_message': encrypted.hex()})
    except Exception as e:
        return jsonify({'error': 'Vui lòng nhấn Generate RSA Keys trước!'}), 500

@app.route('/api/rsa/decrypt', methods=['POST'])
def rsa_decrypt():
    try:
        data = request.json
        ciphertext_hex = data.get('ciphertext', '')
        if not ciphertext_hex:
            return jsonify({'decrypted_message': ''})

        priv_key, _ = rsa_logic.load_keys()
        decrypted = rsa_logic.decrypt(bytes.fromhex(ciphertext_hex), priv_key)
        return jsonify({'decrypted_message': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/sign', methods=['POST'])
def rsa_sign():
    try:
        data = request.json
        priv_key, _ = rsa_logic.load_keys()
        signature = rsa_logic.sign(data['message'], priv_key)
        return jsonify({'signature': signature.hex()})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/rsa/verify', methods=['POST'])
def rsa_verify():
    try:
        data = request.json
        _, pub_key = rsa_logic.load_keys()
        is_verified = rsa_logic.verify(data['message'], bytes.fromhex(data['signature']), pub_key)
        return jsonify({'is_verified': is_verified})
    except Exception as e:
        return jsonify({'is_verified': False, 'error': str(e)}), 500


# ================= ECC ROUTES (MỚI) =================

@app.route('/api/ecc/generate_keys', methods=['GET'])
def gen_ecc_keys():
    try:
        ecc_logic.generate_keys()
        return jsonify({'message': 'ECC Keys generated successfully'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/ecc/sign', methods=['POST'])
def ecc_sign():
    try:
        data = request.json
        message = data.get('message', '')
        # load_keys trả về (sk, vk) tương ứng (private, public)
        priv_key, _ = ecc_logic.load_keys()
        signature = ecc_logic.sign(message, priv_key)
        return jsonify({'signature': signature.hex()})
    except Exception as e:
        return jsonify({'error': 'Vui lòng nhấn Generate ECC Keys trước!'}), 500

@app.route('/api/ecc/verify', methods=['POST'])
def ecc_verify():
    try:
        data = request.json
        message = data.get('message', '')
        signature_hex = data.get('signature', '')
        
        _, pub_key = ecc_logic.load_keys()
        is_verified = ecc_logic.verify(message, bytes.fromhex(signature_hex), pub_key)
        return jsonify({'is_verified': is_verified})
    except Exception as e:
        return jsonify({'is_verified': False, 'error': str(e)}), 500

# ================= CHẠY SERVER =================

if __name__ == "__main__":
    # host="0.0.0.0" cho phép truy cập từ các thiết bị khác trong cùng mạng
    app.run(host="0.0.0.0", port=5000, debug=True)