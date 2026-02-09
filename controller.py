# import requests
# import threading
from flask import Blueprint, jsonify, request
# from utils import extract_whatsapp_text, extract_message_id, load_private_key
from utils import decrypt_aes_key, decrypt_flow_payload, load_private_key

chat_blueprint = Blueprint('chat', __name__)

@chat_blueprint.route("/flow", methods=["GET", "POST"])
def flow():
    private_key = load_private_key()
    body = request.get_json()

    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    try:
        aes_key = decrypt_aes_key(
            private_key,
            body["encrypted_aes_key"]
        )

        decrypted_payload = decrypt_flow_payload(
            aes_key,
            body["encrypted_flow_data"],
            body["initialization_vector"]
        )

    except KeyError as e:
        return jsonify({"error": f"Missing field: {str(e)}"}), 400

    except Exception as e:
        return jsonify({"error": f"Decryption failed: {str(e)}"}), 400

    print("Decrypted Flow Payload:", decrypted_payload)

    return jsonify({"status": "ok"}), 200