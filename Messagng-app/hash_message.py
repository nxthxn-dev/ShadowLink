import rsa

with open("privateKey.pem", "rb") as priv_file:
    privateKey = rsa.PrivateKey.load_pkcs1(priv_file.read())

message = b"Hello, this is a secure message!"

hash_value = rsa.compute_hash(message, "SHA-512")

signature = rsa.sign_hash(hash_value, privateKey, "SHA-512")

with open("signature.sig", "wb") as sig_file:
    sig_file.write(signature)

print("✅ Message Signed!")
