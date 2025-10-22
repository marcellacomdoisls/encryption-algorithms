from Crypto.Cipher import ARC4
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def rc4_encrypt(key, plaintext):
    cipher = ARC4.new(key)
    ciphertext = cipher.encrypt(plaintext.encode('utf-8'))
    return b64encode(ciphertext).decode('utf-8')

def rc4_decrypt(key, b64_ciphertext):
    ciphertext = b64decode(b64_ciphertext)
    cipher = ARC4.new(key)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.decode('utf-8')

key_rc4 = get_random_bytes(16)
data_rc4 = "Esta é uma mensagem secreta para RC4"
encrypted_rc4 = rc4_encrypt(key_rc4, data_rc4)
decrypted_rc4 = rc4_decrypt(key_rc4, encrypted_rc4)

print(encrypted_rc4)
print(decrypted_rc4)