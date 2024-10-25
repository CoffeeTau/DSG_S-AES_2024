import numpy as np
from GF2N import GF2N
from utils import decimalToNpBinary
import time

class SAES:
    def __init__(self, key):
        # 初始化密钥、S盒、逆S盒和扩展密钥
        self.key = key
        self.SBOX = {
            '0000': '1001', '0001': '0100', '0010': '1010', '0011': '1011',
            '0100': '1101', '0101': '0001', '0110': '1000', '0111': '0101',
            '1000': '0110', '1001': '0010', '1010': '0000', '1011': '0011',
            '1100': '1100', '1101': '1110', '1110': '1111', '1111': '0111'
        }
        self.InvSBOX = {
            '0000': '1010', '0001': '0101', '0010': '1001', '0011': '1011',
            '0100': '0001', '0101': '0111', '0110': '1000', '0111': '1111',
            '1000': '0110', '1001': '0000', '1010': '0010', '1011': '0011',
            '1100': '1100', '1101': '0100', '1110': '1101', '1111': '1110'
        }
        self.MixColumnsMatrix = np.array([[1, 4], [4, 1]])
        self.InvMixColumnsMatrix = np.array([[9, 2], [2, 9]])
        self.consList = np.array([[1, 0, 0, 0, 0, 0, 0, 0], [0, 0, 1, 1, 0, 0, 0, 0]])
        self.expandedKeys = self.keyExpansion(key)

        self.GF2N = GF2N(4, 0b10011)  # 有限域生成类  GF(2^4)  不可约多项式: 10011

    # ------ GF(2^4) 操作 ------
    def GfAdd(self, a, b):
        return self.GF2N.add(a, b)

    def GfMul(self, a, b):
        return self.GF2N.mul(a, b)

    # ------ 核心加密操作 ------
    def KeyAdd(self, state, key):
        """轮密钥加"""
        return state ^ key

    def SubstituteHalfbyte(self, input_binary, sbox):
        """半字节替代"""
        return sbox[input_binary]

    def EncryptHalfbyte(self, state):
        """加密半字节替代"""
        binary_str = ''.join(map(str, state))
        encrypted = ''.join(self.SubstituteHalfbyte(binary_str[i:i + 4], self.SBOX) for i in range(0, len(binary_str), 4))
        return np.array([int(bit) for bit in encrypted])

    def DecryptHalfbyte(self, state):
        """解密半字节替代"""
        binary_str = ''.join(map(str, state))
        decrypted = ''.join(self.SubstituteHalfbyte(binary_str[i:i + 4], self.InvSBOX) for i in range(0, len(binary_str), 4))
        return np.array([int(bit) for bit in decrypted])

    def DisplaceLine(self, state):
        """行位移"""
        binary_str = ''.join(str(bit) for bit in state)
        new_binary_str = binary_str[:4] + binary_str[12:16] + binary_str[8:12] + binary_str[4:8]
        return np.array([int(bit) for bit in new_binary_str])

    def MixColumns(self, state):
        """列混淆"""
        binary_string = ''.join(str(bit) for bit in state)
        values = [int(binary_string[i:i + 4], 2) for i in range(0, 16, 4)]
        transfer_state = np.array([[values[0], values[2]], [values[1], values[3]]])
        result = np.zeros_like(transfer_state)

        for i in range(transfer_state.shape[1]):
            result[0, i] = self.GfMul(self.MixColumnsMatrix[0, 0], transfer_state[0, i]) ^ self.GfMul(self.MixColumnsMatrix[0, 1], transfer_state[1, i])
            result[1, i] = self.GfMul(self.MixColumnsMatrix[1, 0], transfer_state[0, i]) ^ self.GfMul(self.MixColumnsMatrix[1, 1], transfer_state[1, i])

        return self.MatrixToNpArray(result)

    def InvMixColumns(self, state):
        """逆列混淆"""
        binary_string = ''.join(str(bit) for bit in state)
        values = [int(binary_string[i:i + 4], 2) for i in range(0, 16, 4)]
        transfer_state = np.array([[values[0], values[2]], [values[1], values[3]]])
        result = np.zeros_like(transfer_state)

        for i in range(transfer_state.shape[1]):
            result[0, i] = self.GfMul(self.InvMixColumnsMatrix[0, 0], transfer_state[0, i]) ^ self.GfMul(self.InvMixColumnsMatrix[0, 1], transfer_state[1, i])
            result[1, i] = self.GfMul(self.InvMixColumnsMatrix[1, 0], transfer_state[0, i]) ^ self.GfMul(self.InvMixColumnsMatrix[1, 1], transfer_state[1, i])

        return self.MatrixToNpArray(result)

    def MatrixToNpArray(self, matrix):
        """按列遍历矩阵，将每个元素转换为4位二进制字符串，并拼接"""
        binary_str = ''.join(f'{matrix[i, j]:04b}' for j in range(matrix.shape[1]) for i in range(matrix.shape[0]))
        return np.array([int(bit) for bit in binary_str])

    def xor(self, text1, text2):
        """异或操作"""
        return np.bitwise_xor(text1, text2)

    def G(self, byte_text, cons):
        """g函数：左循环移位、S盒替代、与轮常数异或"""
        res_text = np.concatenate((byte_text[4:], byte_text[:4]))

        result = np.empty_like(res_text)
        for index in range(0, len(res_text), 4):
            i = ''.join(map(str, res_text[index:index + 2]))
            j = ''.join(map(str, res_text[index + 2:index + 4]))
            sbox_value = self.SBOX[i + j]
            result[index:index + 4] = np.array(list(map(int, sbox_value)))
        return self.xor(result, cons)

    def circleExpand(self, key, cons):
        """轮函数：生成密钥的左、右部分"""
        left_key, right_key = key[:8], key[8:]
        res_left = self.xor(self.G(right_key, cons), left_key)
        res_right = self.xor(res_left, right_key)
        return np.concatenate((res_left, res_right))

    def keyExpansion(self, key):
        """密钥扩展函数：生成多个轮密钥"""
        sub_keys = [key]
        for i in range(2):
            key = self.circleExpand(key, self.consList[i])
            sub_keys.append(key)
        return np.array(sub_keys)

    # ------------------------------------第一轮加密 --------------------------
    def encryptFirstRound(self, state):
        """第一轮加密：字节替代、行移位、列混淆、轮密钥加"""
        state = self.EncryptHalfbyte(state)
        state = self.DisplaceLine(state)
        state = self.MixColumns(state)
        return self.KeyAdd(state, self.expandedKeys[1])

    # ------------------------------------第二轮加密 --------------------------
    def encryptSecondRound(self, state):
        """第二轮加密：半字节替代、行移位、轮密钥加"""
        state = self.EncryptHalfbyte(state)
        state = self.DisplaceLine(state)
        return self.KeyAdd(state, self.expandedKeys[2])

    # ------------------------------------加密函数 --------------------------
    def encrypt(self, plaintext):
        """加密函数：执行密钥扩展和两轮加密"""
        state = self.KeyAdd(plaintext, self.expandedKeys[0])  # 轮密钥加
        state = self.encryptFirstRound(state)                 # 第一轮加密
        return self.encryptSecondRound(state)                 # 第二轮加密

    # ------------------------------------第一轮解密 --------------------------
    def decryptFirstRound(self, state):
        """第一轮解密：逆行位移、逆半字节替代、轮密钥加、逆列混淆"""
        state = self.DisplaceLine(state)
        state = self.DecryptHalfbyte(state)
        state = self.KeyAdd(state, self.expandedKeys[1])
        return self.InvMixColumns(state)

    # ------------------------------------解密第二轮 --------------------------
    def decryptSecondRound(self, state):
        """第二轮解密：逆行位移、逆半字节替代、轮密钥加"""
        state = self.DisplaceLine(state)
        state = self.DecryptHalfbyte(state)
        return self.KeyAdd(state, self.expandedKeys[0])

    # ------------------------------------解密函数 --------------------------
    def decrypt(self, ciphertext):
        """解密函数：执行密钥扩展和两轮解密"""
        state = self.KeyAdd(ciphertext, self.expandedKeys[2]) # 轮密钥加
        state = self.decryptFirstRound(state)                 # 第一轮解密
        return self.decryptSecondRound(state)                 # 第二轮解密

def meet_in_the_middle_attack(plaintext, ciphertext):
    start_time = time.time()  # 记录开始时间

    possible_keys = range(65536)  # 假设密钥是16位长（0-65535）

    # 存储中间结果的字典
    encrypt_dict = {}
    decrypt_dict = {}

    # 遍历所有可能的 K1，对明文进行加密，存储中间结果
    for k1 in possible_keys:
        k1_bin = np.array([int(bit) for bit in f'{k1:016b}'])
        saes = SAES(key=k1_bin)
        intermediate = saes.encrypt(plaintext)
        intermediate_str = ''.join(map(str, intermediate))  # 将中间结果转换为字符串
        encrypt_dict[intermediate_str] = k1

    # 遍历所有可能的 K2，对密文进行解密，存储中间结果
    for k2 in possible_keys:
        k2_bin = np.array([int(bit) for bit in f'{k2:016b}'])
        saes = SAES(key=k2_bin)
        intermediate = saes.decrypt(ciphertext)
        intermediate_str = ''.join(map(str, intermediate))  # 将中间结果转换为字符串
        decrypt_dict[intermediate_str] = k2

    # 查找相同的中间结果
    for intermediate_str in encrypt_dict:
        if intermediate_str in decrypt_dict:
            k1 = encrypt_dict[intermediate_str]
            k2 = decrypt_dict[intermediate_str]
            k1 = decimalToNpBinary(k1)
            k2 = decimalToNpBinary(k2)

            print(f"找到密钥对: K1={k1}, K2={k2}")

            end_time = time.time()
            time_use = end_time - start_time

            print("执行中间相遇攻击所需时间:", time_use)
            return k1, k2, time_use

    print("未找到匹配的密钥对")
    return None, None,

if __name__ == "__main__":
    # 明文和密钥定义
    plaintext = np.array([0, 1, 0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 1, 0])  # 16位明文
    k1_real = np.array([1, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0, 0, 0])  # 16位密钥 K1
    k2_real = np.array([1, 1, 0, 1, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0])  # 16位密钥 K2

    # 初始化加密系统
    saes_k1 = SAES(key=k1_real)
    saes_k2 = SAES(key=k2_real)

    # 加密过程
    intermediate = saes_k1.encrypt(plaintext)
    ciphertext = saes_k2.encrypt(intermediate)  # 使用 K2 对中间值进行加密，得到最终的密文

    print(f"明文: {plaintext}")
    print(f"密钥 K1: {k1_real}")
    print(f"密钥 K2: {k2_real}")
    print(f"对应的密文: {ciphertext}")

    # 执行中间相遇攻击
    # 这个中间相遇攻击找出的k1和k2不一定和前面的k1_real还有k2_real一样
    k1, k2, use_time = meet_in_the_middle_attack(plaintext, ciphertext)
