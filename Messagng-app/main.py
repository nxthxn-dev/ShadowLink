import os
import rsa
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from typing import Dict, List

apu = FastAPI()
messages: List[Dict] = []
clients: List[WebSocket] = []

# Ensure keys directory exists
KEYS_DIR = "keys"
if not os.path.exists(KEYS_DIR):
    os.makedirs(KEYS_DIR)

# Load stored public keys for signature verification
public_keys = {}
if os.path.exists(f"{KEYS_DIR}/public_keys.db"):
    with open(f"{KEYS_DIR}/public_keys.db", "r") as file:
        for line in file:
            username, key_data = line.strip().split(":", 1)
            public_keys[username] = rsa.PublicKey.load_pkcs1(key_data.encode())

print(f"✅ Loaded {len(public_keys)} public keys.")

@apu.post("/send/")
async def send_message(message: dict):
    sender = message["sender"]
    encrypted_message = bytes.fromhex(message["content"])
    signature = bytes.fromhex(message["signature"])

    # Load sender's private key for decryption
    private_key_path = f"{KEYS_DIR}/{sender}_private.pem"
    if not os.path.exists(private_key_path):
        return {"error": f"❌ Private key for {sender} not found."}

    with open(private_key_path, "rb") as priv_file:
        private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())

    # Decrypt message
    decrypted_message = rsa.decrypt(encrypted_message, private_key).decode()

    # Verify digital signature using sender's public key
    if sender not in public_keys:
        return {"error": f"❌ Public key for {sender} not found."}

    try:
        rsa.verify(decrypted_message.encode(), signature, public_keys[sender])
        status = "✅ Verified"
    except rsa.VerificationError:
        status = "❌ Signature Failed"

    # Log message details
    log_msg = (
        f"🔒 Encrypted: {message['content']}\n"
        f"🔓 Decrypted: {decrypted_message}\n"
        f"🛡️ Status: {status}"
    )
    print(log_msg)

    # Store & broadcast message
    formatted_message = {"sender": sender, "content": decrypted_message, "status": status}
    messages.append(formatted_message)
    await broadcast_message(formatted_message)

    return {"status": "Message received", "verification": status}

@apu.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            await broadcast_message(data)
    except WebSocketDisconnect:
        clients.remove(websocket)

async def broadcast_message(message: dict):
    for client in clients:
        await client.send_json(message)
