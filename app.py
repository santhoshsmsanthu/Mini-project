from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

app = Flask(__name__)
CORS(app)

private_key = None
public_key = None

def generate_keys():
    global private_key, public_key
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

def serialize_key(key, is_private=False):
    if is_private:
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode('utf-8')
    return key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode('utf-8')

def bytes_to_format(data, fmt):
    if fmt == "hex":
        return data.hex()
    elif fmt == "binary":
        return ''.join(format(byte, '08b') for byte in data)
    return None

def format_to_bytes(data, fmt):
    if fmt == "hex":
        return bytes.fromhex(data)
    elif fmt == "binary":
        return bytes(int(data[i:i + 8], 2) for i in range(0, len(data), 8))
    return None

def encrypt_message(message, fmt):
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return bytes_to_format(encrypted, fmt)

def decrypt_message(encrypted_message, fmt):
    encrypted_bytes = format_to_bytes(encrypted_message, fmt)
    decrypted = private_key.decrypt(
        encrypted_bytes,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
    )
    return decrypted.decode('utf-8')

@app.route('/')
def index():
    return "RSA Encryption and Decryption API is running."

@app.route('/generate', methods=['POST'])
def generate():
    try:
        generate_keys()
        return jsonify({
            "public_key": serialize_key(public_key),
            "private_key": serialize_key(private_key, is_private=True)
        })
    except Exception as e:
        return jsonify({"error": f"Key generation failed: {str(e)}"}), 500

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.get_json()
    message = data.get('message', '')
    fmt = data.get('format', 'binary')
    if not message:
        return jsonify({"error": "Message is required"}), 400
    try:
        encrypted_message = encrypt_message(message, fmt)
        return jsonify({"ciphertext": encrypted_message})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.get_json()
    encrypted_message = data.get('ciphertext', '')
    fmt = data.get('format', 'binary')
    if not encrypted_message:
        return jsonify({"error": "Ciphertext is required"}), 400
    try:
        decrypted_message = decrypt_message(encrypted_message, fmt)
        return jsonify({"plaintext": decrypted_message})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
