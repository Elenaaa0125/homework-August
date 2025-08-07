import random
import hashlib
from phe import paillier  # 加法同态加密
from sympy import randprime  # 大素数生成

# --------------------------
# 配置参数
# --------------------------
PRIME_BITS = 128  # 群素数位数（实际应用需>=2048）
DEBUG = True  # 打印调试信息


# --------------------------
# DDH群实现
# --------------------------
class DDHGroup:
    def __init__(self):
        self.p = self._generate_large_prime()
        self.g = 2  # 简单生成元
        if DEBUG:
            print(f"[DDHGroup] 素数 p = {self.p}")

    def _generate_large_prime(self):
        """生成密码学安全的大素数"""
        return randprime(2 ** (PRIME_BITS - 1), 2 ** PRIME_BITS)

    def hash_to_group(self, identifier: str) -> int:
        """哈希字符串到群元素（模拟随机预言机）"""
        h = int(hashlib.sha256(identifier.encode()).hexdigest(), 16) % self.p
        return pow(self.g, h, self.p)

    def random_exponent(self) -> int:
        """生成随机私钥"""
        return random.randint(1, self.p - 2)


# --------------------------
# 参与方P1（拥有集合V）
# --------------------------
class Party1:
    def __init__(self, group: DDHGroup, V: list):
        self.group = group
        self.V = V
        self.k1 = group.random_exponent()
        if DEBUG:
            print(f"[P1] 初始化完成，私钥 k1 = {self.k1}")

    def round1(self) -> list:
        """发送 H(v_i)^k1 (乱序)"""
        hashed_V = [pow(self.group.hash_to_group(v), self.k1, self.group.p) for v in self.V]
        random.shuffle(hashed_V)  # 随机排列
        if DEBUG:
            print(f"[P1] Round1发送 {len(hashed_V)} 个哈希值")
        return hashed_V

    def round3(self, Z: list, encrypted_data: list, pk: paillier.PaillierPublicKey) -> paillier.EncryptedNumber:
        """计算交集并返回加密的和"""
        # 计算 H(w_j)^(k1 k2)
        processed = [
            (pow(h_w_k2, self.k1, self.group.p), enc_t)
            for h_w_k2, enc_t in encrypted_data
        ]

        # 找交集
        Z_set = set(Z)
        intersection_enc = [
            enc_t for h_w_k1k2, enc_t in processed
            if h_w_k1k2 in Z_set
        ]

        # 同态求和
        sum_enc = sum(intersection_enc) if intersection_enc else pk.encrypt(0)
        if DEBUG:
            print(f"[P1] Round3找到 {len(intersection_enc)} 个交集元素，求和密文 = {sum_enc.ciphertext()}")
        return sum_enc


# --------------------------
# 参与方P2（拥有集合W={(w, t)}）
# --------------------------
class Party2:
    def __init__(self, group: DDHGroup, W: list):
        self.group = group
        self.W = W
        self.k2 = group.random_exponent()
        self.pk, self.sk = paillier.generate_paillier_keypair()  # 同态加密密钥对
        if DEBUG:
            print(f"[P2] 初始化完成，私钥 k2 = {self.k2}")
            print(f"[P2] Paillier公钥 n = {self.pk.n}")

    def round2(self, hashed_V: list) -> tuple:
        """返回 (Z, 加密数据)"""
        # 计算 Z = H(v_i)^(k1 k2)
        Z = [pow(h_v_k1, self.k2, self.group.p) for h_v_k1 in hashed_V]
        random.shuffle(Z)

        # 加密自己的数据 (H(w_j)^k2, Enc(t_j))
        encrypted_data = []
        for w, t in self.W:
            h_w_k2 = pow(self.group.hash_to_group(w), self.k2, self.group.p)
            enc_t = self.pk.encrypt(t)
            encrypted_data.append((h_w_k2, enc_t))
        random.shuffle(encrypted_data)

        if DEBUG:
            print(f"[P2] Round2发送 {len(Z)} 个Z值和 {len(encrypted_data)} 个加密数据")
        return Z, encrypted_data

    def output(self, sum_enc: paillier.EncryptedNumber) -> int:
        """解密得到最终和"""
        result = self.sk.decrypt(sum_enc)
        if DEBUG:
            print(f"[P2] 解密结果 = {result}")
        return result


# --------------------------
# 主协议执行
# --------------------------
def main():
    print("=== 私有交集求和协议开始 ===")

    # 初始化群和输入数据
    group = DDHGroup()
    V = ["user1", "user2", "user3"]  # P1的集合
    W = [("user2", 50), ("user3", 30), ("user4", 20)]  # P2的集合（带数值）

    # 双方初始化
    p1 = Party1(group, V)
    p2 = Party2(group, W)

    # 协议执行
    print("\n=== Round 1 ===")
    hashed_V = p1.round1()  # P1 -> P2

    print("\n=== Round 2 ===")
    Z, encrypted_data = p2.round2(hashed_V)  # P2 -> P1

    print("\n=== Round 3 ===")
    sum_enc = p1.round3(Z, encrypted_data, p2.pk)  # P1 -> P2

    print("\n=== 结果 ===")
    result = p2.output(sum_enc)  # P2解密
    print(f"\n最终交集数值之和: {result}")


if __name__ == "__main__":
    main()
