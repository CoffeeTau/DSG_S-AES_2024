import numpy as np

def decimalToNpBinary(num):
    # 将密钥转换为二进制并去掉 '0b' 前缀
    bin_num = bin(num)[2:]

    # 将二进制字符串转换为 NumPy 数组，0 和 1
    np_binary_array = np.array([int(bit) for bit in bin_num])

    return np_binary_array