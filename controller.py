import base64
import json
from flask import Blueprint, request, Response
from utils import decrypt_aes_key, decrypt_flow_payload, load_private_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

chat_blueprint = Blueprint('chat', __name__)

@chat_blueprint.route("/flow", methods=["POST"])
def flow():
    """
    WhatsApp Flow endpoint using AES-GCM for response encryption.
    - Decrypt incoming AES key
    - Decrypt incoming payload
    - Encrypt response payload using AES-GCM with bitwise-inverted IV
    - Append auth tag to ciphertext
    - Return Base64-encoded result
    """

    private_key = load_private_key()
    body = request.get_json()

    if not body:
        return Response(status=400)

    # 1️⃣ Decrypt AES key from request
    aes_key = decrypt_aes_key(private_key, body["encrypted_aes_key"])

    # 2️⃣ Decrypt the incoming flow payload
    decrypted_payload = decrypt_flow_payload(
        aes_key,
        body["encrypted_flow_data"],
        body["initial_vector"]
    )
    print("Decrypted Payload:", decrypted_payload)

    # 3️⃣ Prepare response payload
    response_json = {"status": "ok"}
    response_bytes = json.dumps(response_json).encode("utf-8")  # UTF-8 bytes

    # 4️⃣ Prepare IV for response encryption by bitwise inverting the request IV
    request_iv_bytes = base64.b64decode(body["initial_vector"])
    response_iv_bytes = bytes(b ^ 0xFF for b in request_iv_bytes)  # invert all bits

    # 5️⃣ Encrypt using AES-GCM
    aesgcm = AESGCM(aes_key)
    # empty AAD, 16-byte auth tag is default
    encrypted_bytes = aesgcm.encrypt(
        nonce=response_iv_bytes,
        data=response_bytes,
        associated_data=None  # empty AAD
    )
    # Note: AESGCM.encrypt() returns ciphertext + auth tag automatically

    # 6️⃣ Base64 encode the result
    response_base64 = base64.b64encode(encrypted_bytes).decode("utf-8")

    # 7️⃣ Return Base64-encoded response as plain text
    return Response(response=response_base64, status=200, mimetype="text/plain")