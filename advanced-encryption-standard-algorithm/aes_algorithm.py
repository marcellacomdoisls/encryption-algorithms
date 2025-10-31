from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

BLOCK_SIZE = 16
KEY_SIZE = 32


def criptografar_aes_cbc(texto_simples: str, chave: bytes) -> tuple[bytes, bytes]:

    iv = get_random_bytes(BLOCK_SIZE)

    cifrador = AES.new(chave, AES.MODE_CBC, iv)

    dados_preenchidos = pad(texto_simples.encode('utf-8'), BLOCK_SIZE)

    texto_cifrado = cifrador.encrypt(dados_preenchidos)

    return texto_cifrado, iv


def descriptografar_aes_cbc(texto_cifrado: bytes, iv: bytes, chave: bytes) -> str:

    descifrador = AES.new(chave, AES.MODE_CBC, iv)

    dados_descriptografados = descifrador.decrypt(texto_cifrado)

    texto_simples = unpad(dados_descriptografados, BLOCK_SIZE).decode('utf-8')

    return texto_simples


def testar_implementacao():
    print("--- Teste de Implementação AES-256 (Modo CBC) ---")

    chave_secreta = get_random_bytes(KEY_SIZE)
    print(f"Chave (Hex): {chave_secreta.hex()}")

    texto_original = "Esta é uma mensagem secreta para o teste de AES. A criptografia funciona!"
    print(f"Texto Original: {texto_original}")

    texto_cifrado, iv_usado = criptografar_aes_cbc(texto_original, chave_secreta)

    print(f"IV (Hex): {iv_usado.hex()}")
    print(f"Texto Cifrado (Hex): {texto_cifrado.hex()}")
    print(f"Texto Cifrado (Tamanho): {len(texto_cifrado)} bytes")

    texto_recuperado = descriptografar_aes_cbc(texto_cifrado, iv_usado, chave_secreta)

    print(f"Texto Recuperado: {texto_recuperado}")

    if texto_original == texto_recuperado:
        print("\n✅ **SUCESSO:** A implementação de Criptografia e Descriptografia funciona corretamente!")
    else:
        print("\n❌ **FALHA:** O texto recuperado não corresponde ao original.")

    print("-----------------------------------------------------")

if __name__ == "__main__":
    testar_implementacao()