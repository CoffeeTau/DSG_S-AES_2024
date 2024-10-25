class GF2N:
    def __init__(self, n, poly):
        self.n = n
        self.poly = poly  # 不可约多项式，用于模运算，最高位是 n 次方

    # GF(2^n) 上的加法 (按位异或)
    def add(self, a, b):
        return a ^ b  # 按位异或

    # GF(2^n) 上的乘法
    def mul(self, a, b):
        result = 0
        for i in range(self.n):
            if b & (1 << i):      # 检查 b 的每一位
                result ^= a << i  # a * b 的每一位对应的部分相加
        return self.mod(result)

    # 对不可约多项式取模，保证多项式结果落在 GF(2^n) 中
    def mod(self, p):
        # 获取生成多项式的阶数
        poly_deg = self.poly.bit_length() - 1
        while int(p).bit_length() > poly_deg:
            # 将 p 减去一个多项式（相当于取模运算）
            shift = int(p).bit_length() - poly_deg
            p ^= self.poly << (shift - 1)
        return p

    # 求乘法逆元，使用扩展欧几里得算法
    def inverse(self, a):
        if a == 0:
            return 0  # 0 没有逆元
        t, new_t = 0, 1
        r, new_r = self.poly, a
        while new_r != 0:
            quotient = r // new_r
            t, new_t = new_t, t ^ self.mul(quotient, new_t)
            r, new_r = new_r, r ^ self.mul(quotient, new_r)
        return t


if __name__ == "__main__":
    # 构建 GF(2^4) 使用不可约多项式 x^4 + x + 1 (0b10011)
    gf2_4 = GF2N(4, 0b10011)

    # 加法和乘法
    a = 0b0011  # 元素 a
    b = 0b0101  # 元素 b

    add_result = gf2_4.add(a, b)
    mul_result = gf2_4.mul(a, b)

    add_result, mul_result

