import socket
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# =========================
# Server long-term identity key
# =========================
server_identity_key = ec.generate_private_key(ec.SECP256R1())
server_identity_public = server_identity_key.public_key()

print(server_identity_key)
print(server_identity_public)

print("Server public key (give this to client):")
print(server_identity_public.public_bytes(
    encoding=serialization.Encoding.DER,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).hex())


# =========================
# Helpers
# =========================
def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("Connection closed")
        data += chunk
    return data


# =========================
# Handle one client
# =========================
def handle_client(conn):
    print("Client connected")

    try:
        # --- 1. Read timestamp ---
        timestamp = struct.unpack(">Q", recv_exact(conn, 8))[0]

        # --- 2. Nonce ---
        nonce_len = struct.unpack(">I", recv_exact(conn, 4))[0]
        nonce = recv_exact(conn, nonce_len)

        # --- 3. Session public key ---
        sess_len = struct.unpack(">I", recv_exact(conn, 4))[0]
        client_session_pub_bytes = recv_exact(conn, sess_len)

        # --- 4. Identity public key ---
        id_len = struct.unpack(">I", recv_exact(conn, 4))[0]
        client_identity_pub_bytes = recv_exact(conn, id_len)

        # --- 5. Signature ---
        sig_len = struct.unpack(">I", recv_exact(conn, 4))[0]
        signature = recv_exact(conn, sig_len)

        print("Received handshake")
        print("Timestamp:", timestamp)
        print("Nonce:", nonce)

        # --- Reconstruct public keys ---
        client_identity_pub = serialization.load_der_public_key(client_identity_pub_bytes)
        client_session_pub = serialization.load_der_public_key(client_session_pub_bytes)

        # --- Verify signature ---
        signed_data = (
            struct.pack(">Q", timestamp) +
            struct.pack(">I", nonce_len) + nonce +
            struct.pack(">I", sess_len) + client_session_pub_bytes +
            struct.pack(">I", id_len) + client_identity_pub_bytes
        )

        client_identity_pub.verify(
            signature,
            signed_data,
            ec.ECDSA(hashes.SHA256())
        )

        print("Signature valid ✅")

        # --- Generate server session key ---
        server_session_key = ec.generate_private_key(ec.SECP256R1())
        server_session_pub = server_session_key.public_key()

        server_session_pub_bytes = server_session_pub.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # --- Derive shared secret ---
        shared_secret = server_session_key.exchange(ec.ECDH(), client_session_pub)

        # Optional: derive AES key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=16,
            salt=None,
            info=b'handshake',
        ).derive(shared_secret)

        print("Shared key established 🔐")

        # --- Sign server response ---
        to_sign = (
            struct.pack(">I", len(server_session_pub_bytes)) +
            server_session_pub_bytes
        )

        signature = server_identity_key.sign(
            to_sign,
            ec.ECDSA(hashes.SHA256())
        )

        # --- Send ServerHello ---
        response = (
            struct.pack(">I", len(server_session_pub_bytes)) +
            server_session_pub_bytes +
            struct.pack(">I", len(signature)) +
            signature
        )

        conn.sendall(response)
        print("Sent ServerHello")

        # --- Now you could keep reading encrypted data... ---
        # (not implemented, since you said it's not main focus)

    except Exception as e:
        print("Error:", e)

    finally:
        conn.close()
        print("Connection closed\n")


# =========================
# Main server loop
# =========================
def main():
    HOST = "0.0.0.0"
    PORT = 9090

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()

        print(f"Server listening on {PORT}...")

        while True:
            conn, addr = s.accept()
            handle_client(conn)


if __name__ == "__main__":
    main()