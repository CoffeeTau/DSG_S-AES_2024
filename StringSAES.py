import numpy as np
import base64
from SAES import SAES

class StringSAES:
    def __init__(self, key):
        self.saes = SAES(key)

    def padString(self, s):
        
        padding_length = 2 - (len(s) % 2)
        padding_char = chr(padding_length).encode('utf-8')
        return s.encode('utf-8') + padding_char * padding_length

    def unpadString(self, s):
        
        padding_length = s[-1]
        return s[:-padding_length].decode('utf-8')

    def encryptString(self, s):
        
        padded_s = self.padString(s)
        encrypted_array = []

        for i in range(0, len(padded_s), 2):
            
            block = padded_s[i:i + 2]
            block_bits = np.array([int(bit) for byte in block for bit in format(byte, '08b')])

            if block_bits.size != 16:
                raise ValueError("Block size should be 16 bits.")

            encrypted_block = self.saes.encrypt(block_bits)
            encrypted_array.extend(encrypted_block)

        encrypted_bytes = int(''.join(map(str, encrypted_array)), 2).to_bytes(len(encrypted_array) // 8, byteorder='big')
        
        encrypted_string = base64.b64encode(encrypted_bytes).decode('utf-8')
        return encrypted_string

    def decryptString(self, s):

        encrypted_bytes = base64.b64decode(s)
        
        s_bits = [int(bit) for bit in ''.join(format(byte, '08b') for byte in encrypted_bytes)]
        decrypted_array = []

        for i in range(0, len(s_bits), 16):
           
            block = np.array(s_bits[i:i + 16])

            if block.size != 16:
                raise ValueError("Block size should be 16 bits.")

            decrypted_block = self.saes.decrypt(block)
            decrypted_array.extend(decrypted_block)

        decrypted_bytes = int(''.join(map(str, decrypted_array)), 2).to_bytes(len(decrypted_array) // 8, byteorder='big')

        return self.unpadString(decrypted_bytes)

if __name__ == "__main__":

    key = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])
    encryptor = StringSAES(key)
    
    plaintext = "Hello, SAES!"
    print("Original plaintext:", plaintext)

    encrypted = encryptor.encryptString(plaintext)
    print("Encrypted:", encrypted)

    decrypted = encryptor.decryptString(encrypted)
    print("Decrypted:", decrypted)
