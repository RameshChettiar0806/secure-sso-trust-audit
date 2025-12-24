from flask import Flask, jsonify
from auth.jwt_basic import generate_rsa_keypair, create_jwt, verify_jwt
from auth.attacker import attacker_keypair, forge_token

app = Flask(__name__)

# Legitimate Identity Provider keys
PRIVATE_KEY, PUBLIC_KEY = generate_rsa_keypair()

# Attacker-controlled keys
ATTACKER_PRIVATE, ATTACKER_PUBLIC = attacker_keypair()


@app.route("/login")
def login():
    token = create_jwt(PRIVATE_KEY)
    return jsonify({"token": token})


@app.route("/verify")
def verify():
    try:
        token = create_jwt(PRIVATE_KEY)
        payload = verify_jwt(token, PUBLIC_KEY)
        return jsonify({
            "status": "valid (legitimate issuer)",
            "payload": payload
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401


@app.route("/attack")
def attack():
    try:
        forged_token = forge_token(ATTACKER_PRIVATE)

        # Vulnerability: verifier trusts any RSA public key
        payload = verify_jwt(forged_token, ATTACKER_PUBLIC)

        return jsonify({
            "status": "accepted forged token",
            "payload": payload,
            "security_issue": "issuer not trusted"
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 401


if __name__ == "__main__":
    app.run(debug=True)
