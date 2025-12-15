import os
import json
from flask import Flask, request, jsonify
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
import requests
import time

app = Flask(__name__)

# ---------------------------------------
PUBLIC_KEY = "pridajte_vase"
APPLICATION_ID = "pridajte_vase"
# ---------------------------------------


def verify_signature(req):
    signature = req.headers.get("X-Signature-Ed25519")
    timestamp = req.headers.get("X-Signature-Timestamp")
    body = req.data.decode("utf-8")

    if not signature or not timestamp:
        return False

    try:
        key = VerifyKey(bytes.fromhex(PUBLIC_KEY))
        key.verify(
            (timestamp + body).encode(),
            bytes.fromhex(signature)
        )
        return True
    except BadSignatureError:
        return False


@app.route("/interactions", methods=["POST"])
def interactions():
    if not verify_signature(request):
        return "invalid signature", 401

    data = request.json

    # Discord ping
    if data["type"] == 1:
        return jsonify({"type": 1})

    # Slash command
    if data["type"] == 2:
        command = data["data"]["name"]

        if command == "sayapp":
            send_followups(data)
            return jsonify({"type": 5})   # deferred message
    return jsonify({"type": 4, "data": {"content": "Unknown command"}})


def send_followups(interaction):
    token = interaction["token"]

    url = f"https://discord.com/api/v10/webhooks/{APPLICATION_ID}/{token}"

    message = "NEBULA ON TOP\nINV: https://discord.gg/rQsZh77Trw"

    for i in range(3):
        payload = {
            "content": message,
            "allowed_mentions": {"parse": []}
        }
        requests.post(url, json=payload)
        time.sleep(0.4)


if __name__ == "__main__":
    app.run(port=pridajte_vas_port)
