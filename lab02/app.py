from flask import Flask, render_template, request, json
from cipher.caesar import CaesarCipher
from cipher.vigenere import VigenereCipher
from cipher.railfence import RailFenceCipher
from cipher.playfair import PlayFairCipher
from cipher.transposition import TranspositionCipher
app = Flask(__name__)
@app.route("/")
def home():
    return render_template('index.html')
# --- CAESAR CIPHER SECTION ---
@app.route("/caesar")
def caesar():
    return render_template('caesar.html')
@app.route("/encrypt", methods=['POST'])
def caesar_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    Caesar = CaesarCipher()
    encrypted_text = Caesar.encrypt_text(text, key)
    return f"text: {text}<br>key: {key}<br>encrypted text: {encrypted_text}"
@app.route("/decrypt", methods=['POST'])
def caesar_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    Caesar = CaesarCipher()
    decrypted_text = Caesar.decrypt_text(text, key)
    return f"text: {text}<br>key: {key}<br>decrypted text: {decrypted_text}"
# --- VIGENERE CIPHER SECTION ---
@app.route("/vigenere")
def vigenere():
    return render_template('vigenere.html')
@app.route("/vigenere/encrypt", methods=['POST'])
def vigenere_web_encrypt():
    text = request.form['inputPlainText']
    key = request.form['inputKeyPlain'] 
    Vigenere = VigenereCipher()
    encrypted_text = Vigenere.vigenere_encrypt(text, key)
    return f"text: {text}<br>key: {key}<br>encrypted text: {encrypted_text}"
@app.route("/vigenere/decrypt", methods=['POST'])
def vigenere_web_decrypt():
    text = request.form['inputCipherText']
    key = request.form['inputKeyCipher']
    Vigenere = VigenereCipher()
    decrypted_text = Vigenere.vigenere_decrypt(text, key)
    return f"text: {text}<br>key: {key}<br>decrypted text: {decrypted_text}"
# --- RAIL FENCE SECTION ---
@app.route("/railfence")
def railfence():
    return render_template('railfence.html')
@app.route("/railfence/encrypt", methods=['POST'])
def railfence_web_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain']) 
    rf = RailFenceCipher()
    encrypted_text = rf.rail_fence_encrypt(text, key)
    return f"text: {text}<br>key: {key}<br>encrypted text: {encrypted_text}"
@app.route("/railfence/decrypt", methods=['POST'])
def railfence_web_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    rf = RailFenceCipher()
    decrypted_text = rf.rail_fence_decrypt(text, key)
    return f"text: {text}<br>key: {key}<br>decrypted text: {decrypted_text}"

# --- PLAYFAIR CIPHER SECTION ---
@app.route("/playfair")
def playfair():
    return render_template('playfair.html')
@app.route("/playfair/encrypt", methods=['POST'])
def playfair_web_encrypt():
    text = request.form['inputPlainText']
    key = request.form['inputKeyPlain']
    pf = PlayFairCipher()
    encrypted_text = pf.playfair_encrypt(text, key)
    return f"text: {text}<br>key: {key}<br>encrypted text: {encrypted_text}"
@app.route("/playfair/decrypt", methods=['POST'])
def playfair_web_decrypt():
    text = request.form['inputCipherText']
    key = request.form['inputKeyCipher']
    pf = PlayFairCipher()
    decrypted_text = pf.playfair_decrypt(text, key)
    return f"text: {text}<br>key: {key}<br>decrypted text: {decrypted_text}"

# --- TRANSPOSITION CIPHER SECTION ---
@app.route("/transposition")
def transposition():
    return render_template('transposition.html')
@app.route("/transposition/encrypt", methods=['POST'])
def transposition_web_encrypt():
    text = request.form['inputPlainText']
    key = int(request.form['inputKeyPlain'])
    tc = TranspositionCipher()
    encrypted_text = tc.transposition_encrypt(text, key)
    return f"text: {text}<br>key: {key}<br>encrypted text: {encrypted_text}"
@app.route("/transposition/decrypt", methods=['POST'])
def transposition_web_decrypt():
    text = request.form['inputCipherText']
    key = int(request.form['inputKeyCipher'])
    tc = TranspositionCipher()
    decrypted_text = tc.transposition_decrypt(text, key)
    return f"text: {text}<br>key: {key}<br>decrypted text: {decrypted_text}"


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5050, debug=True)