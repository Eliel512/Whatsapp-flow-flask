import base64
import json
from flask import Blueprint, request, Response
from utils import decrypt_aes_key, decrypt_flow_payload, load_private_key
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

chat_blueprint = Blueprint('chat', __name__)

@chat_blueprint.route("/flow", methods=["POST"])
def flow():
    private_key = load_private_key()
    body = request.get_json()

    if not body:
        return Response(status=400)

    # Decrypt AES key from incoming request
    aes_key = decrypt_aes_key(private_key, body["encrypted_aes_key"])
    decrypted_payload = decrypt_flow_payload(
        aes_key,
        body["encrypted_flow_data"],
        body["initial_vector"]
    )
    print("Decrypted Payload:", decrypted_payload)

    # Prepare plaintext JSON response
    response_json = {"status": "ok"}
    response_bytes = json.dumps(response_json).encode("utf-8")

    # AES-CBC encryption with PKCS7 padding
    iv = body.get("initial_vector")  # WhatsApp expects same IV sometimes
    if iv:
        iv = base64.b64decode(iv)
    else:
        from os import urandom
        iv = urandom(16)

    padder = padding.PKCS7(128).padder()
    padded = padder.update(response_bytes) + padder.finalize()

    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(padded) + encryptor.finalize()

    # Prepend IV (if needed) and Base64 encode
    response_base64 = base64.b64encode(iv + encrypted).decode("utf-8")

    return Response(response=response_base64, status=200, mimetype="text/plain")