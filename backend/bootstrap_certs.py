from crypto.cert_utils import generate_root_ca, generate_idp_cert, save_pem
import os

os.makedirs("certs", exist_ok=True)

root_key, root_cert = generate_root_ca()
idp_key, idp_cert = generate_idp_cert(root_key, root_cert)

save_pem(root_cert, "certs/root_ca.pem")
save_pem(idp_cert, "certs/idp_cert.pem")
save_pem(idp_key, "certs/idp_key.pem", is_private=True)

print("[+] Root CA and IdP certificates generated")
