import numpy as np
from GF2N import GF2N
class SBoxBuild:
    def __init__(self, gf2n, linear_matrix, constant):
        self.gf2n = gf2n
        self.linear_matrix = linear_matrix
        self.constant = constant

    def build_sbox(self):
        """
        构建 S 盒。
        :return: 生成的 S 盒
        """
        sbox = {}
        for x in range(16):  # 对应 4 位二进制数，从 0 到 15
            # 1. 求逆元（注意 0 没有逆元，保留为 0）
            inv_x = self.gf2n.inverse(x) if x != 0 else 0

            # 2. 将逆元表示为比特串
            inv_x_bits = [(inv_x >> i) & 1 for i in range(4)]

            # 3. 线性变换：矩阵乘法和常量加
            transformed_bits = np.dot(self.linear_matrix, inv_x_bits) % 2
            transformed_bits = np.bitwise_xor(transformed_bits, self.constant)

            # 4. 转换为十进制整数并存入 S 盒
            sbox_value = sum([int(b) << i for i, b in enumerate(transformed_bits)])
            sbox[f'{x:04b}'] = f'{sbox_value:04b}'

        return sbox

    def build_inv_sbox(self, sbox):
        """
        构建逆 S 盒。
        :param sbox: S 盒
        :return: 生成的逆 S 盒
        """
        inv_sbox = {v: k for k, v in sbox.items()}
        return inv_sbox


if __name__ == "__main__":
    gf2_4 = GF2N(4, 0b10011)

    # 定义线性变换矩阵 Y 和常量 D
    linear_matrix = np.array([[1, 0, 0, 0],
                              [1, 1, 0, 0],
                              [1, 1, 1, 0],
                              [1, 1, 1, 1]])

    constant = np.array([0, 1, 0, 0])  # 常量 D

    # 构建 S 盒类
    sbox_builder = SBoxBuild(gf2_4, linear_matrix, constant)

    # 构建 S 盒及其逆 S 盒
    sbox = sbox_builder.build_sbox()
    inv_sbox = sbox_builder.build_inv_sbox(sbox)

    # 打印 S 盒和逆 S 盒
    print("S-Box:", sbox)
    print("Inverse S-Box:", inv_sbox)