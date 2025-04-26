import os
import rsa
import sqlite3
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Request
from pydantic import BaseModel
from typing import Dict, List

# FastAPI app
apu = FastAPI()
messages: List[Dict] = []
clients: List[WebSocket] = []

# Constants
KEYS_DIR = "keys"
DB_PATH = "keys/public_keys.db"
os.makedirs(KEYS_DIR, exist_ok=True)

# Database setup
def setup_database():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                public_key BLOB
            )
        """)
        conn.commit()

setup_database()

# User registration model
class UserModel(BaseModel):
    username: str

# Message model
class MessageModel(BaseModel):
    sender: str
    receiver: str
    content: str

# Encryption model
class EncryptedMessageModel(BaseModel):
    sender: str
    receiver: str
    encrypted_content: List[str]  # Store encrypted chunks as a list
    signature: str

def generate_keys(username: str):
    """Generates RSA key pair for a new user if not already registered."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE username = ?", (username,))
        if cursor.fetchone():
            return None, None  # User already registered

        # Generate new key pair
        public_key, private_key = rsa.newkeys(2048)

        # Save private key in a file
        private_key_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
        with open(private_key_path, "wb") as priv_file:
            priv_file.write(private_key.save_pkcs1())

        # Store public key in database
        cursor.execute("INSERT INTO users (username, public_key) VALUES (?, ?)", 
                       (username, public_key.save_pkcs1()))
        conn.commit()

    return public_key, private_key

def get_public_key(username: str):
    """Retrieves a user's public key from the database."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT public_key FROM users WHERE username = ?", (username,))
        row = cursor.fetchone()
    
    if row:
        return rsa.PublicKey.load_pkcs1(row[0])
    return None

def get_private_key(username: str):
    """Retrieves a user's private key from the file system."""
    private_key_path = os.path.join(KEYS_DIR, f"{username}_private.pem")
    if os.path.exists(private_key_path):
        with open(private_key_path, "rb") as priv_file:
            return rsa.PrivateKey.load_pkcs1(priv_file.read())
    return None

def encrypt_message(message: str, public_key):
    """Splits and encrypts a message in chunks to avoid overflow error."""
    max_length = 245  # Maximum size for RSA encryption with a 2048-bit key
    encrypted_chunks = []

    for i in range(0, len(message), max_length):
        chunk = message[i:i+max_length].encode()
        encrypted_chunks.append(rsa.encrypt(chunk, public_key).hex())

    return encrypted_chunks

def decrypt_message(encrypted_chunks: List[str], private_key):
    """Decrypts a list of encrypted message chunks."""
    decrypted_message = ""

    for chunk in encrypted_chunks:
        decrypted_message += rsa.decrypt(bytes.fromhex(chunk), private_key).decode()

    return decrypted_message

@apu.post("/register/")
async def register_user(user: UserModel):
    """Registers a new user and generates RSA keys."""
    public_key, _ = generate_keys(user.username)
    if public_key is None:
        return {"status": "⚠️ User already registered", "username": user.username}
    return {"status": "✅ User registered", "username": user.username}

@apu.post("/get_public_key/")
async def get_public_key_endpoint(user: UserModel):
    """Fetches a user's public key."""
    public_key = get_public_key(user.username)
    if not public_key:
        raise HTTPException(status_code=404, detail="❌ Public key not found.")
    
    return {"username": user.username, "public_key": public_key.save_pkcs1().decode()}

@apu.get("/list_users/")
async def list_users():
    """Lists all registered users."""
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users")
        users = cursor.fetchall()

    return {"users": [user[0] for user in users]}

@apu.post("/send/")
async def send_message(request: Request):
    """Encrypts and signs a message before sending."""
    try:
        data = await request.json()  # Get raw JSON data
        print("Received data:", data)  # Debugging output
    except Exception as e:
        return {"status": "❌ Error parsing request", "detail": str(e)}

    sender_private = get_private_key(data["sender"])
    receiver_public = get_public_key(data["receiver"])

    if not sender_private or not receiver_public:
        return {"status": "❌ Sender or receiver keys not found."}

    try:
        encrypted_chunks = encrypt_message(data["content"], receiver_public)
        signature = rsa.sign(data["content"].encode(), sender_private, 'SHA-512')
    except Exception as e:
        return {"status": "❌ Encryption/Signing failed", "detail": str(e)}

    formatted_message = {
        "sender": data["sender"],
        "receiver": data["receiver"],
        "encrypted_content": encrypted_chunks,
        "signature": signature.hex(),
    }
    messages.append(formatted_message)
    await broadcast_message(formatted_message)

    return {
        "status": "✅ Message sent",
        "encrypted_chunks": encrypted_chunks,
        "signature": signature.hex()
    }

@apu.post("/receive/")
async def receive_message(encrypted_message: EncryptedMessageModel):
    """Decrypts a received message and verifies the signature."""
    sender_public = get_public_key(encrypted_message.sender)
    receiver_private = get_private_key(encrypted_message.receiver)

    if not receiver_private or not sender_public:
        raise HTTPException(status_code=404, detail="❌ Receiver or sender keys not found.")

    try:
        decrypted_message = decrypt_message(encrypted_message.encrypted_content, receiver_private)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"❌ Decryption failed: {str(e)}")

    try:
        rsa.verify(decrypted_message.encode(), bytes.fromhex(encrypted_message.signature), sender_public)
        status = "✅ Verified"
    except rsa.VerificationError:
        status = "❌ Signature Failed"

    formatted_message = {"sender": encrypted_message.sender, "content": decrypted_message, "status": status}
    messages.append(formatted_message)
    await broadcast_message(formatted_message)

    return {"status": "Message received", "verification": status, "decrypted_message": decrypted_message}

@apu.delete("/clear/")
async def clear_messages():
    """Clears all stored messages."""
    messages.clear()
    return {"status": "✅ Chat cleared."}

@apu.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Handles WebSocket connections for real-time messaging."""
    await websocket.accept()
    clients.append(websocket)
    try:
        while True:
            data = await websocket.receive_json()
            await broadcast_message(data)
    except WebSocketDisconnect:
        clients.remove(websocket)

async def broadcast_message(message: dict):
    """Broadcasts messages to all connected WebSocket clients."""
    for client in clients:
        try:
            await client.send_json(message)
        except Exception:
            clients.remove(client)
