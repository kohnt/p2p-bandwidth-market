import asyncio
import json
import base64
import struct
import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def load_server_private():
# Load private key
    with open("server_private_key.der", "rb") as f:
        server_identity_key = serialization.load_der_private_key(f.read(), password=None)
    return server_identity_key

def load_server_public():
    # Load public key
    with open("server_public_key.der", "rb") as f:
        server_identity_public = serialization.load_der_public_key(f.read())
    return server_identity_public

# --- CONFIGURATION ---
# IMPORTANT: You must use the private key corresponding to the public key in your Android KeyManager.
# This is a placeholder. Generate your static key and load it here.
SERVER_PRIVATE_KEY_PEM = load_server_private()
SERVER_PUBLIC_KEY = load_server_public()

# Store session keys indexed by peer address or identity
sessions = {}

async def handle_handshake(reader, writer, data_str):
    try:
        packet = json.loads(data_str)
        print(f"[*] Received Handshake from {writer.get_extra_info('peername')}")

        client_id_pub_bytes = base64.b64decode(packet['identity_pub'])
        client_session_pub_bytes = base64.b64decode(packet['session_pub'])
        client_nonce_bytes = base64.b64decode(packet['nonce'])

        # 1. Load Client Session Public Key
        client_session_pub = serialization.load_der_public_key(client_session_pub_bytes)

        # 2. Generate Server Session Key & Shared Secret (ECDH)
        server_session_priv = ec.generate_private_key(ec.SECP256R1())
        shared_secret = server_session_priv.exchange(ec.ECDH(), client_session_pub)

        # 3. Derive AES Key (Matches KeyManager.java: SHA-256 KDF)
        aes_key = hashlib.sha256(shared_secret).digest()[:16] # AES-128

        # 4. Create Signature for Server Reply
        # Format must match Android's verification: (UserSessionPub | UserNonce)
        to_sign = struct.pack(f">I{len(client_session_pub_bytes)}sI{len(client_nonce_bytes)}s", 
                              len(client_session_pub_bytes), client_session_pub_bytes,
                              len(client_nonce_bytes), client_nonce_bytes)
        
        signature = SERVER_PRIVATE_KEY_PEM.sign(to_sign, ec.ECDSA(hashes.SHA256()))

        # 5. Build Response
        response = {
            "session_pub": base64.b64encode(server_session_priv.public_key().public_bytes(
                serialization.Encoding.X509, serialization.PublicFormat.SubjectPublicKeyInfo)).decode(),
            "nonce": base64.b64encode(b"server-nonce").decode(),
            "signature": base64.b64encode(signature).decode()
        }
        
        writer.write(json.dumps(response).encode())
        await writer.drain()
        
        # Save session for the relay phase
        sessions[writer.get_extra_info('peername')[0]] = aes_key
        print("[+] Handshake Complete. Session Key established.")

    except Exception as e:
        print(f"[!] Handshake Error: {e}")

async def relay_data(reader, writer, aes_key):
    aesgcm = AESGCM(aes_key)
    target_writer = None

    try:
        while True:
            # 1. Read 4-byte length prefix (Big Endian)
            len_data = await reader.readexactly(4)
            length = struct.unpack(">I", len_data)[0]
            
            # 2. Read full encrypted payload (IV + Ciphertext + Tag)
            encrypted_payload = await reader.readexactly(length)
            
            # 3. Decrypt (First 12 bytes are IV)
            iv = encrypted_payload[:12]
            ciphertext = encrypted_payload[12:]
            decrypted = aesgcm.decrypt(iv, ciphertext, None)

            if target_writer is None:
                # FIRST PACKET: Contains target host and port
                host_len = struct.unpack(">I", decrypted[:4])[0]
                host = decrypted[4:4+host_len].decode()
                port = struct.unpack(">I", decrypted[4+host_len:4+host_len+4])[0]
                
                print(f"[*] Connecting to target: {host}:{port}")
                t_reader, t_writer = await asyncio.open_connection(host, port)
                target_writer = t_writer
                asyncio.create_task(relay_back(t_reader, writer, aesgcm))
            else:
                # SUBSEQUENT PACKETS: Plain data to be forwarded to internet
                target_writer.write(decrypted)
                await target_writer.drain()

    except Exception as e:
        print(f"[*] Connection closed: {e}")
    finally:
        if target_writer: target_writer.close()
        writer.close()

async def relay_back(target_reader, client_writer, aesgcm):
    """Reads from internet and sends encrypted data back to Android"""
    try:
        while True:
            data = await target_reader.read(4096)
            if not data: break
            
            # Encrypt
            iv = AESGCM.generate_nonce(12)
            encrypted = aesgcm.encrypt(iv, data, None)
            payload = iv + encrypted
            
            # Send Length + Payload
            client_writer.write(struct.pack(">I", len(payload)) + payload)
            await client_writer.drain()
    except Exception:
        pass

async def main_handler(reader, writer):
    # Detect if it's a JSON handshake or binary data
    peek = await reader.read(2048)
    print("RECEIVED:", peek)
    if not peek: return

    if peek.startswith(b'{'):
        await handle_handshake(reader, writer, peek.decode())
        writer.close()
    else:
        # For relaying, we look up the AES key generated in the handshake phase
        client_ip = writer.get_extra_info('peername')[0]
        if client_ip in sessions:
            # We use the 'peeked' data as the start of the binary stream
            # But the binary stream starts with a 4-byte length. 
            # We need to process 'peek' as the beginning of the stream.
            class ReplayReader:
                def __init__(self, first, r): self.first, self.r = first, r
                async def readexactly(self, n):
                    if self.first:
                        res = self.first[:n]
                        self.first = self.first[n:]
                        if len(res) < n:
                            res += await self.r.readexactly(n - len(res))
                        return res
                    return await self.r.readexactly(n)

            await relay_data(ReplayReader(peek, reader), writer, sessions[client_ip])
        else:
            print(f"[!] Unauthorized connection from {client_ip}")
            writer.close()

async def start():
    server = await asyncio.start_server(main_handler, '0.0.0.0', 9999)
    print("[*] Server listening on port 9999...")
    async with server: await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(start())
