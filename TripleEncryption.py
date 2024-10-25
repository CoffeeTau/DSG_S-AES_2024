from SAES import SAES
import numpy as np
from GF2N import GF2N

class tripleEncryptionThreeKeys:
    def __init__(self, key1, key2, key3):
        self.saes1 = SAES(key1)
        self.saes2 = SAES(key2)
        self.saes3 = SAES(key3)

    def encrypt(self, plaintext):
        # 进行三重加密
        ciphertext = self.saes1.encrypt(plaintext)
        ciphertext = self.saes2.decrypt(ciphertext)
        ciphertext = self.saes3.encrypt(ciphertext)
        return ciphertext

    def decrypt(self, ciphertext):
        # 进行三重解密
        plaintext = self.saes3.decrypt(ciphertext)
        plaintext = self.saes2.encrypt(plaintext)
        plaintext = self.saes1.decrypt(plaintext)
        return plaintext
    
class tripleEncryptionTwoKeys:
    def __init__(self, key1, key2):
        self.saes1 = SAES(key1)
        self.saes2 = SAES(key2)
        self.saes3 = SAES(key1)

    def encrypt(self, plaintext):
        # 进行三重加密
        ciphertext = self.saes1.encrypt(plaintext)
        ciphertext = self.saes2.decrypt(ciphertext)
        ciphertext = self.saes3.encrypt(ciphertext)
        return ciphertext

    def decrypt(self, ciphertext):
        # 进行三重解密
        plaintext = self.saes3.decrypt(ciphertext)
        plaintext = self.saes2.encrypt(plaintext)
        plaintext = self.saes1.decrypt(plaintext)
        return plaintext
    
if __name__ == "__main__":

    # 三重加密 三个密钥
    # key1 = np.array([0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])  # 示例初始密钥
    # key2 = np.array([1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1])  # 示例初始密钥
    # key3 = np.array([1, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 1, 0, 1, 0, 1])  # 示例初始密钥
        
    
    # triple_encrypt = tripleEncryptionThreeKeys(key1, key2, key3)

    # plaintext = np.array([0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    # ciphertext = triple_encrypt.encrypt(plaintext)
    # print("密文.........................................................................")
    # print(ciphertext)

    # if np.array_equal(plaintext, triple_encrypt.decrypt(ciphertext)):

    #     print("测试成功。")
    # else:
    #     print(triple_encrypt.decrypt(ciphertext, key1, key2, key3))
    #     print("测试不成功。")

    # 三重加密 两个密钥
    key1 = np.array([0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])  # 示例初始密钥
    key2 = np.array([1, 1, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1])  # 示例初始密钥
    
    triple_encrypt = tripleEncryptionTwoKeys(key1, key2)

    plaintext = np.array([0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])
    ciphertext = triple_encrypt.encrypt(plaintext)
    print("密文.........................................................................")
    print(ciphertext)

    if np.array_equal(plaintext, triple_encrypt.decrypt(ciphertext)):

        print("测试成功。")
    else:
        print(triple_encrypt.decrypt(ciphertext, key1, key2))
        print("测试不成功。")