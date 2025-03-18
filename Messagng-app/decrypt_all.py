import rsa

with open("publicKey.pem", "rb") as pub_file:
    publicKey = rsa.PublicKey.load_pkcs1(pub_file.read())

message = b"Hello, this is a secure message!"
with open("signature.sig", "rb") as sig_file:
    signature = sig_file.read()

try:
    rsa.verify(message, signature, publicKey)
    print("✅ Signature Verified!")
except rsa.VerificationError:
    print("❌ Signature Verification Failed!")
