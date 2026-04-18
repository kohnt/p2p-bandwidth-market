"""
relay_server.py — P2P Bandwidth Market relay server

Protocol (all frames use [4-byte big-endian length][UTF-8 JSON body]):

  Handshake connection (one-shot, then closed):
    Client → {"type":"handshake","timestamp":<ms>,"nonce":<b64>,
               "identity_pub":<b64 DER>,"session_pub":<b64 DER>}
    Server → {"session_pub":<b64 DER>,"session_token":<hex str>}

  Seller registration (persistent connection):
    Seller → {"type":"seller_register","seller_token":<uuid str>}
    Server → {"status":"ok"}
    Server → {"type":"relay_open",  "session_id":<str>,"target_host":<str>,"target_port":<int>}
    Server → {"type":"relay_data",  "session_id":<str>,"data":<b64>}
    Server → {"type":"relay_close", "session_id":<str>}
    Seller → {"type":"relay_data",  "session_id":<str>,"data":<b64>}
    Seller → {"type":"relay_close", "session_id":<str>}

  Relay connection (buyer, persistent):
    Client → {"type":"hello","session":<token>,"target_host":<str>,"target_port":<int>,
               "seller":<seller_token>}   ← omit "seller" to use EC2's own internet
    Client → {"type":"relay","session":<token>,"data":<b64 raw bytes>}  (repeated)
    Server → {"type":"data","data":<b64 raw bytes>}                     (repeated)

Keys:
  server_private_key.der — PKCS#8 EC private key (SECP256R1)
  server_public_key.der  — matching SubjectPublicKeyInfo public key
"""

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Key loading
# ---------------------------------------------------------------------------

def _load_server_private() -> ec.EllipticCurvePrivateKey:
    with open("server_private_key.der", "rb") as f:
        return serialization.load_der_private_key(f.read(), password=None)

def _load_server_public() -> ec.EllipticCurvePublicKey:
    with open("server_public_key.der", "rb") as f:
        return serialization.load_der_public_key(f.read())
# ---------------------------------------------------------------------------
# Replay protection (simple + in-memory)
# ---------------------------------------------------------------------------

_seen_nonces: dict[bytes, int] = {}
NONCE_WINDOW_MS = 300_000  # 5 minutes

def check_replay(nonce: bytes, timestamp: int):
    now = int(time.time() * 1000)

    # 1. timestamp freshness
    if abs(now - timestamp) > NONCE_WINDOW_MS:
        raise ValueError("Timestamp outside allowed window")

    # 2. nonce reuse
    if nonce in _seen_nonces:
        raise ValueError("Replay detected (nonce reused)")

    # 3. store nonce
    _seen_nonces[nonce] = timestamp

    # 4. cleanup old entries
    cutoff = now - NONCE_WINDOW_MS
    expired = [n for n, ts in _seen_nonces.items() if ts < cutoff]
    for n in expired:
        del _seen_nonces[n]

SERVER_PRIVATE_KEY = _load_server_private()
SERVER_PUBLIC_KEY  = _load_server_public()

# session_token (str) → aes_key (bytes, 16-byte AES-128)
_sessions: dict[str, bytes] = {}

# seller_token (str) → SellerConnection
_sellers: dict[str, "SellerConnection"] = {}

# ---------------------------------------------------------------------------
# Seller connection state
# ---------------------------------------------------------------------------

class SellerConnection:
    def __init__(self, writer: asyncio.StreamWriter):
        self.writer = writer
        # session_id → Queue[bytes | None]  (None = closed sentinel)
        self.session_queues: dict[str, asyncio.Queue] = {}

    async def open_session(self, session_id: str, target_host: str, target_port: int) -> "asyncio.Queue[bytes | None]":
        q: asyncio.Queue = asyncio.Queue()
        self.session_queues[session_id] = q
        await write_frame(self.writer, {
            "type":        "relay_open",
            "session_id":  session_id,
            "target_host": target_host,
            "target_port": target_port,
        })
        return q

    async def send_data(self, session_id: str, data: bytes) -> None:
        await write_frame(self.writer, {
            "type":       "relay_data",
            "session_id": session_id,
            "data":       base64.b64encode(data).decode(),
        })

    async def close_session(self, session_id: str) -> None:
        self.session_queues.pop(session_id, None)
        try:
            await write_frame(self.writer, {
                "type":       "relay_close",
                "session_id": session_id,
            })
        except Exception:
            pass

# ---------------------------------------------------------------------------
# AES-128-GCM helpers — [12-byte IV][ciphertext + 16-byte tag]
# ---------------------------------------------------------------------------

def aes_decrypt(aes_key: bytes, data: bytes) -> bytes:
    return AESGCM(aes_key).decrypt(data[:12], data[12:], None)

def aes_encrypt(aes_key: bytes, plaintext: bytes) -> bytes:
    iv = os.urandom(12)
    return iv + AESGCM(aes_key).encrypt(iv, plaintext, None)

# ---------------------------------------------------------------------------
# Framed I/O helpers
# ---------------------------------------------------------------------------

async def read_frame(reader: asyncio.StreamReader) -> bytes:
    len_buf = await reader.readexactly(4)
    length = struct.unpack(">I", len_buf)[0]
    if length == 0 or length > 1_048_576:
        raise ValueError(f"Implausible frame length: {length}")
    return await reader.readexactly(length)

async def write_frame(writer: asyncio.StreamWriter, obj: dict) -> None:
    body = json.dumps(obj).encode("utf-8")
    writer.write(struct.pack(">I", len(body)) + body)
    await writer.drain()

# ---------------------------------------------------------------------------
# EC public key loader with explicit-params fallback
# ---------------------------------------------------------------------------

def _load_ec_public_key(der_bytes: bytes):
    """Load a SubjectPublicKeyInfo EC public key from DER bytes.

    Some Android OEM devices (e.g. OPPO/Realme) encode EC keys using explicit
    curve parameters instead of the standard named-curve OID.  OpenSSL 3.x
    rejects explicit-params keys, so load_der_public_key raises an X509 error.
    In that case, extract the raw uncompressed EC point (04 || x || y) and
    reconstruct a P-256 key object directly.
    """
    try:
        return serialization.load_der_public_key(der_bytes)
    except Exception:
        # Locate the uncompressed point marker (0x04) followed by exactly 64 bytes.
        idx = der_bytes.rfind(b'\x04')
        if idx != -1 and len(der_bytes) - idx == 65:
            raw = der_bytes[idx:]
            x = int.from_bytes(raw[1:33], 'big')
            y = int.from_bytes(raw[33:65], 'big')
            from cryptography.hazmat.primitives.asymmetric.ec import (
                EllipticCurvePublicNumbers, SECP256R1,
            )
            log.warning("[handshake] explicit-params EC key detected — using raw-point fallback")
            return EllipticCurvePublicNumbers(x, y, SECP256R1()).public_key()
        raise ValueError(f"Cannot parse EC public key ({len(der_bytes)} bytes)")

# ---------------------------------------------------------------------------
# Handshake handler
# ---------------------------------------------------------------------------

async def handle_handshake(reader: asyncio.StreamReader,
                            writer: asyncio.StreamWriter,
                            first_frame: bytes) -> None:
    peer = writer.get_extra_info("peername")
    try:
        packet = json.loads(first_frame.decode("utf-8"))
        if packet.get("type") != "handshake":
            raise ValueError("Expected type=handshake")

        client_identity_pub_bytes = base64.b64decode(packet["identity_pub"])
        client_session_pub_bytes  = base64.b64decode(packet["session_pub"])
        nonce_a                   = base64.b64decode(packet["nonce"])
        client_sig                = base64.b64decode(packet["client_sig"])
        timestamp                 = int(packet["timestamp"])

        check_replay(nonce_a, timestamp)

        print("Server in packet: ")
        print({
            "client_identity_pub_bytes":packet["identity_pub"],
            "client_session_pub_bytes":packet["session_pub"],
            "nonce_a":packet["nonce"],
            "client_sig":packet["client_sig"],
            "timestamp":int(packet["timestamp"])
        })

        # Step 1 — verify client signed: "handshake" || timestamp(8-byte BE) || nonceA || identity_pub_DER || session_pub_DER
        client_identity_pub = _load_ec_public_key(client_identity_pub_bytes)
        to_verify = (
            b"handshake"
            + struct.pack(">q", timestamp)
            + nonce_a
            + client_identity_pub_bytes
            + client_session_pub_bytes
        )
        try:
            client_identity_pub.verify(client_sig, to_verify, ec.ECDSA(hashes.SHA256()))
        except Exception as exc:
            raise ValueError(f"Client signature verification failed: {exc}") from exc

        # ECDH
        client_session_pub   = _load_ec_public_key(client_session_pub_bytes)
        server_session_priv  = ec.generate_private_key(ec.SECP256R1())
        shared_secret        = server_session_priv.exchange(ec.ECDH(), client_session_pub)
        aes_key              = hashlib.sha256(shared_secret).digest()[:16]
        session_token        = secrets.token_hex(16)
        _sessions[session_token] = aes_key

        server_session_pub_bytes = server_session_priv.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        # Step 2 — sign: server_session_pub_DER || session_pub_A_DER || nonceA || nonceS
        nonce_s    = os.urandom(16)
        to_sign    = server_session_pub_bytes + client_session_pub_bytes + nonce_a + nonce_s
        server_sig = SERVER_PRIVATE_KEY.sign(to_sign, ec.ECDSA(hashes.SHA256()))

        print("Server out packet: ")
        print({
            "session_pub":   base64.b64encode(server_session_pub_bytes).decode(),
            "session_token": session_token,
            "nonce_s":       base64.b64encode(nonce_s).decode(),
            "server_sig":    base64.b64encode(server_sig).decode(),
        }) 

        await write_frame(writer, {
            "session_pub":   base64.b64encode(server_session_pub_bytes).decode(),
            "session_token": session_token,
            "nonce_s":       base64.b64encode(nonce_s).decode(),
            "server_sig":    base64.b64encode(server_sig).decode(),
        })
        log.info("[handshake] OK — token=%s peer=%s", session_token, peer)

    except Exception as exc:
        log.warning("[handshake] FAILED from %s: %s", peer, exc)
    finally:
        writer.close()

# ---------------------------------------------------------------------------
# Payment handler
# ---------------------------------------------------------------------------

async def handle_payment(reader: asyncio.StreamReader,
                          writer: asyncio.StreamWriter,
                          first_frame: bytes) -> None:
    peer = writer.get_extra_info("peername")
    try:
        packet    = json.loads(first_frame.decode("utf-8"))
        amount_mb = int(packet.get("amount_mb", 0))
        if amount_mb <= 0:
            raise ValueError(f"Invalid amount_mb: {amount_mb}")

        payment_token = secrets.token_hex(16)
        await write_frame(writer, {
            "status":        "ok",
            "payment_token": payment_token,
        })
        log.info("[payment] OK — %d MB token=%s peer=%s", amount_mb, payment_token, peer)

    except Exception as exc:
        log.warning("[payment] FAILED from %s: %s", peer, exc)
        try:
            await write_frame(writer, {"status": "error", "error": str(exc)})
        except Exception:
            pass
    finally:
        writer.close()

# ---------------------------------------------------------------------------
# Seller registration handler
# ---------------------------------------------------------------------------

async def handle_seller(reader: asyncio.StreamReader,
                         writer: asyncio.StreamWriter,
                         first_frame: bytes) -> None:
    peer = writer.get_extra_info("peername")
    seller_token = None
    try:
        packet = json.loads(first_frame.decode("utf-8"))
        seller_token = packet.get("seller_token", "")
        if not seller_token:
            raise ValueError("Missing seller_token")

        conn = SellerConnection(writer)
        _sellers[seller_token] = conn
        await write_frame(writer, {"status": "ok"})
        log.info("[seller] registered token=%s peer=%s", seller_token, peer)

        while True:
            raw        = await read_frame(reader)
            msg        = json.loads(raw.decode("utf-8"))
            msg_type   = msg.get("type")
            session_id = msg.get("session_id", "")

            if msg_type == "relay_data":
                q = conn.session_queues.get(session_id)
                if q:
                    await q.put(base64.b64decode(msg["data"]))
            elif msg_type == "relay_close":
                q = conn.session_queues.pop(session_id, None)
                if q:
                    await q.put(None)  # closed sentinel
            else:
                log.warning("[seller] unknown frame type %r — ignoring", msg_type)

    except Exception as exc:
        log.info("[seller] disconnected (token=%s peer=%s): %s", seller_token, peer, exc)
    finally:
        if seller_token and _sellers.get(seller_token) and _sellers[seller_token].writer is writer:
            del _sellers[seller_token]
            log.info("[seller] unregistered token=%s", seller_token)
        writer.close()

# ---------------------------------------------------------------------------
# Relay handler
# ---------------------------------------------------------------------------

async def handle_relay(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter,
                        first_frame: bytes) -> None:
    peer = writer.get_extra_info("peername")
    try:
        hello = json.loads(first_frame.decode("utf-8"))
        if hello.get("type") != "hello":
            raise ValueError("Expected type=hello as first relay frame")

        token   = hello.get("session", "")
        aes_key = _sessions.get(token)
        if aes_key is None:
            raise ValueError(f"Unknown session token: {token!r}")

        target_host  = hello["target_host"]
        target_port  = int(hello["target_port"])
        seller_token = hello.get("seller")

        if seller_token:
            await _relay_via_seller(reader, writer, aes_key, target_host, target_port, seller_token, peer)
        else:
            await _relay_direct(reader, writer, aes_key, target_host, target_port, peer)

    except Exception as exc:
        log.info("[relay] closed (%s): %s", peer, exc)
    finally:
        writer.close()


async def _relay_direct(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                         aes_key: bytes, target_host: str, target_port: int, peer) -> None:
    """EC2 connects directly to the target and bridges the encrypted buyer tunnel."""
    log.info("[relay/direct] %s → %s:%s", peer, target_host, target_port)
    t_reader, t_writer = await asyncio.open_connection(target_host, target_port)

    async def target_to_buyer() -> None:
        try:
            while True:
                chunk = await t_reader.read(4096)
                if not chunk:
                    break
                print("Target to buyer plain: ", chunk)
                print("Target to buyer encrypted: ", base64.b64encode(aes_encrypt(aes_key, chunk)).decode())
                await write_frame(writer, {
                    "type": "data",
                    "data": base64.b64encode(aes_encrypt(aes_key, chunk)).decode(),
                })
        except Exception:
            pass

    pipe_task = asyncio.create_task(target_to_buyer())
    try:
        while True:
            raw = await read_frame(reader)
            msg = json.loads(raw.decode("utf-8"))
            if msg.get("type") != "relay":
                log.warning("[relay/direct] unexpected frame type %r — ignoring", msg.get("type"))
                continue
            plaintext = aes_decrypt(aes_key, base64.b64decode(msg["data"]))
            t_writer.write(plaintext)
            await t_writer.drain()
    finally:
        pipe_task.cancel()
        t_writer.close()


async def _relay_via_seller(reader: asyncio.StreamReader, writer: asyncio.StreamWriter,
                              aes_key: bytes, target_host: str, target_port: int,
                              seller_token: str, peer) -> None:
    """Broker traffic through a registered seller device as the exit node."""
    seller = _sellers.get(seller_token)
    if seller is None:
        raise ValueError(f"Seller not connected: {seller_token!r}")

    session_id = secrets.token_hex(8)
    log.info("[relay/seller] %s → seller=%s session=%s target=%s:%s",
             peer, seller_token, session_id, target_host, target_port)

    q = await seller.open_session(session_id, target_host, target_port)

    async def seller_to_buyer() -> None:
        try:
            while True:
                data = await q.get()
                if data is None:
                    break  # seller closed the session
                print("Seller to buyer plain: ", data)
                print("Seller to buyer encrypted: ", base64.b64encode(aes_encrypt(aes_key, data)).decode())
                await write_frame(writer, {
                    "type": "data",
                    "data": base64.b64encode(aes_encrypt(aes_key, data)).decode(),
                })
        except Exception:
            pass

    pipe_task = asyncio.create_task(seller_to_buyer())
    try:
        while True:
            raw = await read_frame(reader)
            msg = json.loads(raw.decode("utf-8"))
            if msg.get("type") != "relay":
                continue
            plaintext = aes_decrypt(aes_key, base64.b64decode(msg["data"]))
            await seller.send_data(session_id, plaintext)
    finally:
        pipe_task.cancel()
        await seller.close_session(session_id)

# ---------------------------------------------------------------------------
# Connection dispatcher
# ---------------------------------------------------------------------------

async def main_handler(reader: asyncio.StreamReader,
                        writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    try:
        first_frame = await read_frame(reader)
        msg         = json.loads(first_frame.decode("utf-8"))
        msg_type    = msg.get("type")

        if msg_type == "handshake":
            await handle_handshake(reader, writer, first_frame)
        elif msg_type == "hello":
            await handle_relay(reader, writer, first_frame)
        elif msg_type == "seller_register":
            await handle_seller(reader, writer, first_frame)
        elif msg_type == "payment":
            await handle_payment(reader, writer, first_frame)
        else:
            log.warning("[dispatch] unknown type %r from %s — dropping", msg_type, peer)
            writer.close()

    except Exception as exc:
        log.warning("[dispatch] error from %s: %s", peer, exc)
        writer.close()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def start() -> None:
    server = await asyncio.start_server(main_handler, "0.0.0.0", 9999)
    addrs  = [s.getsockname() for s in server.sockets]
    log.info("Relay server listening on %s", addrs)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(start())
