import numpy as np
from SAES import SAES
from GF2N import GF2N

class DoubleSAES:
    def __init__(self, key1, key2):
       
        self.SAES1 = SAES(key1)
        self.SAES2 = SAES(key2)
        self.key1 = self.SAES1.expandedKeys
        self.key2 = self.SAES2.expandedKeys

    def DoubleEncrypt(self, plaintext):
        
        MidText = self.SAES1.encrypt(plaintext)
        ciphertext = self.SAES2.encrypt(MidText)

        return ciphertext
    
    def DoubleDecrypt(self, ciphertext):

        MidText = self.SAES2.decrypt(ciphertext)
        plaintext = self.SAES1.decrypt(MidText)
        
        return plaintext

if __name__ == "__main__":

    key1 = np.array([1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0])
    key2 = np.array([0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1])

    double_saes = DoubleSAES(key1, key2)

    plaintext = np.array([1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1])

    ciphertext = double_saes.DoubleEncrypt(plaintext)
    print("加密后的结果为：", ciphertext)


    decrypted_text = double_saes.DoubleDecrypt(ciphertext)
    print("解密后的结果为：", decrypted_text)

    if np.array_equal(plaintext, decrypted_text):
        print("解密成功，恢复了原始明文")
