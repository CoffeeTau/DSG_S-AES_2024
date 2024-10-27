import numpy as np
from SAES import SAES
from GF2N import GF2N
from StringSAES import StringSAES

class DoubleSAES:
    def __init__(self, key1, key2):
        # 使用 StringSAES 类来处理字符串加密
        self.SAES1 = StringSAES(key1)
        self.SAES2 = StringSAES(key2)
        self.key1 = self.SAES1.saes.expandedKeys  # 获取 SAES 实例的扩展密钥
        self.key2 = self.SAES2.saes.expandedKeys

    def DoubleBitEncrypt(self, plaintext):
        # 对位数组进行双重加密
        MidText = self.SAES1.saes.encrypt(plaintext)
        ciphertext = self.SAES2.saes.encrypt(MidText)
        return ciphertext
    
    def DoubleBitDecrypt(self, ciphertext):
        # 对位数组进行双重解密
        MidText = self.SAES2.saes.decrypt(ciphertext)
        plaintext = self.SAES1.saes.decrypt(MidText)
        return plaintext
    
    def DoubleStringEncrypt(self, plaintext):
        # 对字符串进行双重加密
        MidText = self.SAES1.encryptString(plaintext)
        ciphertext = self.SAES2.encryptString(MidText)
        return ciphertext
    
    def DoubleStringDecrypt(self, ciphertext):
        # 对字符串进行双重解密
        MidText = self.SAES2.decryptString(ciphertext)
        plaintext = self.SAES1.decryptString(MidText)
        return plaintext
    

if __name__ == "__main__":
    # 定义两个密钥
    key1 = np.array([1,1,1,1,1,1,1,1,0,0,0,0,0,0,0,0])
    key2 = np.array([0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1])

    # 创建 DoubleSAES 实例
    double_saes = DoubleSAES(key1, key2)

    # 测试字符串加密和解密
    plaintext_string = "gh7ythikjijyu"
    print("Original plaintext:", plaintext_string)

    encrypted_string = double_saes.DoubleStringEncrypt(plaintext_string)
    print("Encrypted string:", encrypted_string)

    decrypted_string = double_saes.DoubleStringDecrypt("vD0URgaKoZt5gfn3QBxPnHdIvo+NCg==")
    print("Decrypted string:", decrypted_string)

    # if plaintext_string == decrypted_string:
    #     print("String decryption successful, original plaintext restored.")

    # # 测试位数组加密和解密
    # plaintext_bits = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])

    # encrypted_bits = double_saes.DoubleBitEncrypt(plaintext_bits)
    # print("加密后的位数组结果为：", encrypted_bits)

    # decrypted_bits = double_saes.DoubleBitDecrypt(encrypted_bits)
    # print("解密后的位数组结果为：", decrypted_bits)

    # if np.array_equal(plaintext_bits, decrypted_bits):
    #     print("位数组解密成功，恢复了原始明文")
