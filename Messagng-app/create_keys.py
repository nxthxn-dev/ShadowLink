import rsa

publicKey, privateKey = rsa.newkeys(2048)

with open("publicKey.pem", "wb") as pub_file:
    pub_file.write(publicKey.save_pkcs1("PEM"))

with open("privateKey.pem", "wb") as priv_file:
    priv_file.write(privateKey.save_pkcs1("PEM"))

print("✅ RSA Keys Generated and Saved!")
