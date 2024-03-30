from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def get_random_number(seed):
    seed = int(str(seed * seed).zfill(12)[3:9])
    return seed

def decrypt(ciphertext_hex, key):
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = bytes.fromhex(ciphertext_hex)
    decrypted_message = cipher.decrypt(ciphertext)
    return unpad(decrypted_message, AES.block_size).decode()

# Example usage
ciphertext_hex = "3f89b111393cb832465fa9b290ff031ac42142a5eaaa23c6bbb4ca6c339d1b3ff01baf18ab8f5507010091f047d55d8563407a0a15c4953fed6e3181e4bb33dea81215f9e3b628426c13f32488deecd7"

# You need to guess the seed used to generate the key.
# This is just an example. In a real scenario, you would need to know at least part of the key or plaintext to guess the seed.
seed_guess = 123456

key = b''
for i in range(8):
    seed_guess = get_random_number(seed_guess)
    key += (seed_guess % (2 ** 16)).to_bytes(2, 'big')

decrypted_message = decrypt(ciphertext_hex, key)
print("Decrypted message:", decrypted_message)
