import os
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend
from flask import Blueprint, jsonify, request, Response
from utils import decrypt_aes_key, decrypt_flow_payload, load_private_key

chat_blueprint = Blueprint('chat', __name__)

@chat_blueprint.route("/flow", methods=["GET", "POST"])
def flow():
    """
    WhatsApp Flow endpoint.
    - Decrypts the incoming payload
    - Prepares and encrypts the response using the same AES key (AES-CBC)
    - Returns Base64-encoded encrypted response
    """

    # Load private key to decrypt the AES key
    private_key = load_private_key()
    body = request.get_json()

    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    try:
        # Decrypt the AES session key
        aes_key = decrypt_aes_key(private_key, body["encrypted_aes_key"])

        # Decrypt the incoming flow payload
        decrypted_payload = decrypt_flow_payload(
            aes_key,
            body["encrypted_flow_data"],
            body["initial_vector"]
        )

    except KeyError as e:
        return jsonify({"error": f"Missing field: {str(e)}"}), 400
    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

    print("Decrypted Flow Payload:", decrypted_payload)

    # ------------------------------------
    # Prepare the response payload
    # ------------------------------------
    response_payload = {
        "status": "ok"
    }

    # Convert response to JSON bytes
    response_bytes = json.dumps(response_payload).encode("utf-8")

    # ------------------------------------
    # Encrypt the response using AES-CBC
    # ------------------------------------
    iv = os.urandom(16)  # Generate a random IV

    # Apply PKCS7 padding
    padder = padding.PKCS7(128).padder()  # AES block size = 128 bits
    padded_data = padder.update(response_bytes) + padder.finalize()

    # Initialize AES-CBC cipher
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_response = encryptor.update(padded_data) + encryptor.finalize()

    # Combine IV + encrypted payload and Base64-encode it
    response_base64 = base64.b64encode(iv + encrypted_response).decode("utf-8")

    # Return the Base64-encoded response
    return Response(
        response=response_base64,
        status=200,
        mimetype="text/plain"
    )