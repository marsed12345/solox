from flask import Flask, request, jsonify, abort
import hmac
import hashlib
import time
import base64

app = Flask(__name__)

VALID_CREDENTIALS = {
    "4244858982": "70F6C1EA0A7F7D8A3FB20889342B26A4FB39B82059E5E171692E3BE31D6331A8"
}

TOKEN_TTL_SECONDS = 5 * 3600

def generate_token(uid: str, secret: str, expiry_ts: int) -> str:
    msg = f"{uid}:{expiry_ts}".encode()
    key = bytes.fromhex(secret) if all(c in "0123456789abcdefABCDEF" for c in secret) else secret.encode()
    sig = hmac.new(key, msg, hashlib.sha256).digest()
    payload = f"{uid}:{expiry_ts}".encode() + b"." + sig
    return base64.urlsafe_b64encode(payload).decode().rstrip("=")

@app.route("/token", methods=["GET"])
def token_route():
    uid = request.args.get("uid")
    password = request.args.get("password")

    if not uid or not password:
        return jsonify({"error": "missing uid or password"}), 400

    expected = VALID_CREDENTIALS.get(uid)
    if expected is None:
        return jsonify({"error": "invalid uid"}), 403

    if password != expected:
        return jsonify({"error": "invalid password"}), 403

    expiry_ts = int(time.time()) + TOKEN_TTL_SECONDS
    token = generate_token(uid, password, expiry_ts)

    return jsonify({
        "token": token,
        "expires_at": expiry_ts
    }), 200

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
