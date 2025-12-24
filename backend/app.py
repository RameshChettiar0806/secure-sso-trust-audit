from flask import Flask, jsonify
from auth.jwt_basic import generate_rsa_keypair, create_jwt, verify_jwt
from auth.attacker import attacker_keypair, forge_token
from auth.jwt_cert import verify_jwt_with_cert, create_jwt_with_cert

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


@app.route("/verify-secure")
def verify_secure():
    """
    Phase 4: Secure endpoint with certificate chain validation.
    
    This endpoint enforces trust by validating the IdP certificate
    against the Root CA before accepting any JWT.
    """
    try:
        token = create_jwt_with_cert()
        payload = verify_jwt_with_cert(token)

        return jsonify({
            "status": "valid (trusted issuer)",
            "payload": payload
        })

    except Exception as e:
        return jsonify({
            "status": "rejected",
            "reason": str(e)
        }), 401


@app.route("/attack-secure")
def attack_secure():
    """
    Phase 4: Attempt to use forged token against secure endpoint.
    
    This demonstrates that certificate validation prevents the attack.
    The forged token will be rejected because the attacker's certificate
    is not signed by the trusted Root CA.
    """
    try:
        forged_token = forge_token(ATTACKER_PRIVATE)

        # This MUST fail
        verify_jwt_with_cert(forged_token)

        return jsonify({
            "status": "ERROR",
            "message": "Attack unexpectedly succeeded"
        }), 500

    except Exception as e:
        return jsonify({
            "status": "attack blocked",
            "reason": str(e)
        }), 401


if __name__ == "__main__":
    app.run(debug=True)
