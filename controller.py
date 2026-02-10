# import requests
# import threading
import base64
import json
from flask import Blueprint, jsonify, request, Response
# from utils import extract_whatsapp_text, extract_message_id, load_private_key
from utils import decrypt_aes_key, decrypt_flow_payload, load_private_key

chat_blueprint = Blueprint('chat', __name__)

@chat_blueprint.route("/flow", methods=["GET", "POST"])
def flow():
    """
    WhatsApp Flow endpoint.
    - Decrypts the incoming encrypted payload
    - Processes the flow data
    - Returns a Base64-encoded response body as required by WhatsApp Flows
    """

    private_key = load_private_key()
    body = request.get_json()

    if not body:
        return jsonify({"error": "Invalid JSON body"}), 400

    try:
        # Decrypt AES session key using our private key
        aes_key = decrypt_aes_key(
            private_key,
            body["encrypted_aes_key"]
        )

        # Decrypt the flow payload
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
    # Prepare response payload
    # ------------------------------------
    response_payload = {
        "status": "ok"
    }

    # Convert response to JSON bytes
    response_bytes = json.dumps(response_payload).encode("utf-8")

    # Base64 encode the response body
    response_base64 = base64.b64encode(response_bytes).decode("utf-8")

    # Return Base64-encoded body (NOT JSON)
    return Response(
        response=response_base64,
        status=200,
        mimetype="text/plain"
    )