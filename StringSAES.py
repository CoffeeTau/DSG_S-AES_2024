import numpy as np
from SAES import SAES

class StringSAES:
    def __init__(self, key):
        self.saes = SAES(key)

    def padString(self, s):
        """填充字符串，使其长度为16的倍数"""
        while len(s) % 2 != 0:  # 确保是16位的倍数
            s += '\0'  # 用空字符填充
        return s

    def encryptString(self, s):
        s = self.padString(s)
        encrypted_binary = ''
        for i in range(0, len(s), 2):  # 每次处理两个字符（16位）
            block = np.array(list(map(int, ''.join(format(ord(c), 'b').zfill(8) for c in s[i:i + 2]))), dtype=np.uint8)
            encrypted_block = self.saes.encrypt(block)
            encrypted_binary += ''.join(str(b) for b in encrypted_block)

        # 将二进制转换为字符串
        encrypted_chars = []
        for i in range(0, len(encrypted_binary), 8):
            num = int(encrypted_binary[i:i + 8], 2)
            encrypted_chars.append(chr(num))
        return ''.join(encrypted_chars)

    def decryptString(self, s):
        # 调用填充函数以确保长度为偶数
        s = self.padString(s)

        decrypted_binary = ''
        for i in range(0, len(s), 2):  # 每次处理两个字符（16位）
            block = np.array(list(map(int, ''.join(format(ord(c), 'b').zfill(8) for c in s[i:i + 2]))), dtype=np.uint8)
            decrypted_block = self.saes.decrypt(block)
            decrypted_binary += ''.join(str(b) for b in decrypted_block)

        decrypted_chars = []
        for i in range(0, len(decrypted_binary), 8):
            num = int(decrypted_binary[i:i + 8], 2)
            decrypted_chars.append(chr(num))

        return ''.join(decrypted_chars).rstrip('\0')  # 去除填充的空字符


if __name__ == "__main__":
    key = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0])  # 16位密钥
    encryptor = StringSAES(key)

    plaintext = "5/÷Æ+"
    print("Original plaintext:", plaintext)

    encrypted = encryptor.encryptString(plaintext)
    print("Encrypted (as string):", encrypted)

    user_input = input("Enter a string to decrypt: ")
    decrypted = encryptor.decryptString(user_input)
    print("Decrypted:", decrypted)
