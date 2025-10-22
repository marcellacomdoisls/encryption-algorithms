from Crypto.Cipher import DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode

def des3_adjust_key_parity(key):
    return DES3.adjust_key_parity(key)

def des3_encrypt(key, plaintext):
    key_adjusted = des3_adjust_key_parity(key)
    cipher = DES3.new(key_adjusted, DES3.MODE_CBC)
    ciphertext_bytes = cipher.encrypt(pad(plaintext.encode('utf-8'), DES3.block_size))
    iv = b64encode(cipher.iv).decode('utf-8')
    ciphertext = b64encode(ciphertext_bytes).decode('utf-8')
    return iv + ':' + ciphertext

def des3_decrypt(key, iv_and_ciphertext):
    iv_b64, ciphertext_b64 = iv_and_ciphertext.split(':')
    iv = b64decode(iv_b64)
    ciphertext_bytes = b64decode(ciphertext_b64)
    key_adjusted = des3_adjust_key_parity(key)
    cipher = DES3.new(key_adjusted, DES3.MODE_CBC, iv)
    decrypted_padded = cipher.decrypt(ciphertext_bytes)
    plaintext = unpad(decrypted_padded, DES3.block_size)
    return plaintext.decode('utf-8')

key_3des = get_random_bytes(24)
data_3des = "Esta é uma mensagem secreta para 3DES"
encrypted_3des = des3_encrypt(key_3des, data_3des)
decrypted_3des = des3_decrypt(key_3des, encrypted_3des)

print(encrypted_3des)
print(decrypted_3des)