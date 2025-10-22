from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def aes_encrypt(key, plaintext):
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), AES.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    return iv + ':' + ciphertext

def aes_decrypt(key, iv_and_ciphertext):
    iv_b64, ciphertext_b64 = iv_and_ciphertext.split(':')
    iv = b64decode(iv_b64)
    ciphertext_bytes = b64decode(ciphertext_b64)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(decrypted_padded, AES.block_size)
    return plaintext.decode('utf-8')

key_aes = get_random_bytes(16)
data_aes = "Esta é uma mensagem secreta para AES"
encrypted_aes = aes_encrypt(key_aes, data_aes)
decrypted_aes = aes_decrypt(key_aes, encrypted_aes)

print(encrypted_aes)
print(decrypted_aes)