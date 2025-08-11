import random
import hashlib
import binascii
from typing import Tuple


# 基础SM2实现
class SM2Base:
    # 国标SM2推荐参数
    def __init__(self):
        self.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        self.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        self.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        self.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        self.Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        self.Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        self.G = (self.Gx, self.Gy)

    # 模逆计算
    def inv_mod(self, a: int, p: int) -> int:
        return pow(a, p - 2, p)

    # 点加法
    def point_add(self, P: Tuple[int, int], Q: Tuple[int, int]) -> Tuple[int, int]:
        if P == (0, 0):
            return Q
        if Q == (0, 0):
            return P
        if P[0] == Q[0] and (P[1] + Q[1]) % self.p == 0:
            return (0, 0)

        if P != Q:
            lam = (Q[1] - P[1]) * self.inv_mod(Q[0] - P[0], self.p) % self.p
        else:
            lam = (3 * P[0] * P[0] + self.a) * self.inv_mod(2 * P[1], self.p) % self.p

        x3 = (lam * lam - P[0] - Q[0]) % self.p
        y3 = (lam * (P[0] - x3) - P[1]) % self.p
        return (x3, y3)

    # 点乘运算
    def point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        R = (0, 0)
        for i in reversed(range(k.bit_length())):
            R = self.point_add(R, R)
            if (k >> i) & 1:
                R = self.point_add(R, P)
        return R

    # 生成密钥对
    def generate_keypair(self) -> Tuple[int, Tuple[int, int]]:
        private_key = random.randint(1, self.n - 1)
        public_key = self.point_mul(private_key, self.G)
        return private_key, public_key

    # 签名
    def sign(self, msg: bytes, private_key: int) -> Tuple[int, int]:
        e = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
        k = random.randint(1, self.n - 1)
        P = self.point_mul(k, self.G)
        r = (e + P[0]) % self.n
        s = (self.inv_mod(1 + private_key, self.n) * (k - r * private_key)) % self.n
        return r, s

    # 验证
    def verify(self, msg: bytes, signature: Tuple[int, int], public_key: Tuple[int, int]) -> bool:
        r, s = signature
        if not (1 <= r < self.n and 1 <= s < self.n):
            return False

        e = int.from_bytes(hashlib.sha256(msg).digest(), 'big')
        t = (r + s) % self.n
        P = self.point_add(
            self.point_mul(s, self.G),
            self.point_mul(t, public_key)
        )
        return (r % self.n) == ((e + P[0]) % self.n)


# 改进版本1：预计算加速
class SM2Optimized1(SM2Base):
    def __init__(self):
        super().__init__()
        self.precomputed = {}
        self._precompute()

    def _precompute(self):
        # 预计算2^i * G
        P = self.G
        for i in range(256):
            self.precomputed[i] = P
            P = self.point_add(P, P)

    def point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        if P == self.G:  # 仅对基点使用预计算
            R = (0, 0)
            for i in range(256):
                if (k >> i) & 1:
                    R = self.point_add(R, self.precomputed[i])
            return R
        else:
            return super().point_mul(k, P)


# 改进版本2：使用Jacobian坐标
class SM2Optimized2(SM2Base):
    def to_jacobian(self, P: Tuple[int, int]) -> Tuple[int, int, int]:
        return (P[0], P[1], 1)

    def from_jacobian(self, P: Tuple[int, int, int]) -> Tuple[int, int]:
        z_inv = self.inv_mod(P[2], self.p)
        return ((P[0] * z_inv * z_inv) % self.p,
                (P[1] * z_inv * z_inv * z_inv) % self.p)

    def jacobian_add(self, P: Tuple[int, int, int], Q: Tuple[int, int, int]) -> Tuple[int, int, int]:
        if P[2] == 0:
            return Q
        if Q[2] == 0:
            return P

        # 计算中间量
        U1 = (P[0] * Q[2] * Q[2]) % self.p
        U2 = (Q[0] * P[2] * P[2]) % self.p
        S1 = (P[1] * Q[2] * Q[2] * Q[2]) % self.p
        S2 = (Q[1] * P[2] * P[2] * P[2]) % self.p

        if U1 == U2:
            if S1 != S2:
                return (0, 0, 1)
            else:
                return self.jacobian_double(P)

        H = U2 - U1
        R = S2 - S1
        H2 = (H * H) % self.p
        H3 = (H * H2) % self.p
        U1H2 = (U1 * H2) % self.p

        x3 = (R * R - H3 - 2 * U1H2) % self.p
        y3 = (R * (U1H2 - x3) - S1 * H3) % self.p
        z3 = (H * P[2] * Q[2]) % self.p

        return (x3, y3, z3)

    def jacobian_double(self, P: Tuple[int, int, int]) -> Tuple[int, int, int]:
        if P[1] == 0:
            return (0, 0, 0)

        ysq = (P[1] * P[1]) % self.p
        S = (4 * P[0] * ysq) % self.p
        M = (3 * P[0] * P[0] + self.a * pow(P[2], 4, self.p)) % self.p

        nx = (M * M - 2 * S) % self.p
        ny = (M * (S - nx) - 8 * ysq * ysq) % self.p
        nz = (2 * P[1] * P[2]) % self.p

        return (nx, ny, nz)

    def point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        Pj = self.to_jacobian(P)
        Rj = (0, 0, 0)
        for i in reversed(range(k.bit_length())):
            Rj = self.jacobian_double(Rj)
            if (k >> i) & 1:
                Rj = self.jacobian_add(Rj, Pj)
        return self.from_jacobian(Rj)


# 测试用例
def test_sm2():
    msg = b"Hello, SM2!"

    print("Testing Base SM2:")
    sm2 = SM2Base()
    priv, pub = sm2.generate_keypair()
    sig = sm2.sign(msg, priv)
    print(f"Signature valid: {sm2.verify(msg, sig, pub)}")

    print("\nTesting Optimized1 (Precomputation):")
    sm2_opt1 = SM2Optimized1()
    sig_opt1 = sm2_opt1.sign(msg, priv)
    print(f"Signature valid: {sm2_opt1.verify(msg, sig_opt1, pub)}")

    print("\nTesting Optimized2 (Jacobian):")
    sm2_opt2 = SM2Optimized2()
    sig_opt2 = sm2_opt2.sign(msg, priv)
    print(f"Signature valid: {sm2_opt2.verify(msg, sig_opt2, pub)}")


# 性能测试
def benchmark():
    import timeit

    sm2 = SM2Base()
    sm2_opt1 = SM2Optimized1()
    sm2_opt2 = SM2Optimized2()
    priv, pub = sm2.generate_keypair()

    def test_base():
        sm2.point_mul(priv, sm2.G)

    def test_opt1():
        sm2_opt1.point_mul(priv, sm2_opt1.G)

    def test_opt2():
        sm2_opt2.point_mul(priv, sm2_opt2.G)

    print("Base SM2 point_mul:", timeit.timeit(test_base, number=100))
    print("Optimized1 point_mul:", timeit.timeit(test_opt1, number=100))
    print("Optimized2 point_mul:", timeit.timeit(test_opt2, number=100))


if __name__ == "__main__":
    test_sm2()
    print("\nBenchmark results:")
    benchmark()