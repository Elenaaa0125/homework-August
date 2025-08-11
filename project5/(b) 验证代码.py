import hashlib
import math


class SignatureMisuseDemo:
    def __init__(self, a, b, p, G, n):
        """
        初始化椭圆曲线参数
        :param a: 曲线参数a
        :param b: 曲线参数b
        :param p: 有限域的素数
        :param G: 基点(生成元)
        :param n: 基点的阶
        """
        self.a = a
        self.b = b
        self.p = p
        self.G = G
        self.n = n

    def hash_message(self, message):
        """生成消息的哈希摘要"""
        hash_bytes = hashlib.sha256(message.encode()).digest()
        return int.from_bytes(hash_bytes, 'big') % self.n

    def mod_inv(self, a, m):
        """模逆元计算"""
        return pow(a, -1, m) if math.gcd(a, m) == 1 else None

    def ec_point_add(self, P, Q):
        """椭圆曲线点加运算"""
        if P == 0: return Q
        if Q == 0: return P

        if P != Q:
            # 两点不同
            delta_x = (P[0] - Q[0]) % self.p
            inv = self.mod_inv(delta_x, self.p)
            if inv is None: return 0  # 无穷远点
            slope = ((P[1] - Q[1]) * inv) % self.p
        else:
            # 点加倍
            inv = self.mod_inv(2 * P[1], self.p)
            slope = ((3 * P[0] ** 2 + self.a) * inv) % self.p

        x = (slope ** 2 - P[0] - Q[0]) % self.p
        y = (slope * (P[0] - x) - P[1]) % self.p
        return [x, y]

    def ec_scalar_mul(self, k, P):
        """椭圆曲线标量乘法"""
        result = 0  # 无穷远点
        current = P
        while k > 0:
            if k % 2 == 1:
                result = self.ec_point_add(result, current)
            current = self.ec_point_add(current, current)
            k = k // 2
        return result

    def ecdsa_sign(self, d, message, k):
        """ECDSA签名生成"""
        e = self.hash_message(message)
        R = self.ec_scalar_mul(k, self.G)
        r = R[0] % self.n
        k_inv = self.mod_inv(k, self.n)
        s = (k_inv * (e + d * r)) % self.n
        return r, s

    def schnorr_sign(self, d, message, k):
        """Schnorr签名生成"""
        R = self.ec_scalar_mul(k, self.G)
        e = self.hash_message(f"{R[0]}{message}")
        s = (k + e * d) % self.n
        return R, s, e

    def demonstrate_k_leakage(self):
        """场景1：k泄露导致私钥泄露"""
        print("\n=== 场景1：临时密钥k泄露导致私钥泄露 ===")
        d = 3  # 真实私钥
        k = 2  # 临时密钥(假设泄露)
        message = "important_message"

        r, s = self.ecdsa_sign(d, message, k)
        e = self.hash_message(message)

        # 攻击者知道k后计算私钥d
        r_inv = self.mod_inv(r, self.n)
        recovered_d = (r_inv * (k * s - e)) % self.n

        print(f"真实私钥 d = {d}")
        print(f"恢复的私钥 d' = {recovered_d}")
        print(f"验证结果: {'成功' if d == recovered_d else '失败'}")

    def demonstrate_k_reuse(self):
        """场景2：k重用导致私钥泄露"""
        print("\n=== 场景2：临时密钥k重用导致私钥泄露 ===")
        d = 3  # 真实私钥
        k = 2  # 重用的临时密钥
        msg1 = "message1"
        msg2 = "message2"

        # 同一用户使用相同k生成两个签名
        r1, s1 = self.ecdsa_sign(d, msg1, k)
        r2, s2 = self.ecdsa_sign(d, msg2, k)

        e1 = self.hash_message(msg1)
        e2 = self.hash_message(msg2)

        # 攻击者利用两个签名恢复k和d
        s_diff_inv = self.mod_inv((s1 - s2) % self.n, self.n)
        recovered_k = ((e1 - e2) * s_diff_inv) % self.n
        r_inv = self.mod_inv(r1, self.n)
        recovered_d = (r_inv * (recovered_k * s1 - e1)) % self.n

        print(f"真实私钥 d = {d}")
        print(f"恢复的临时密钥 k' = {recovered_k}")
        print(f"恢复的私钥 d' = {recovered_d}")
        print(f"验证结果: {'成功' if d == recovered_d else '失败'}")

    def demonstrate_shared_k(self):
        """场景3：多用户使用相同k导致私钥泄露"""
        print("\n=== 场景3：多用户使用相同k导致私钥泄露 ===")
        d1 = 3  # 用户1私钥
        d2 = 5  # 用户2私钥
        k = 2  # 共享的临时密钥
        msg1 = "user1_msg"
        msg2 = "user2_msg"

        # 两个用户使用相同k生成签名
        r1, s1 = self.ecdsa_sign(d1, msg1, k)
        r2, s2 = self.ecdsa_sign(d2, msg2, k)

        e1 = self.hash_message(msg1)
        e2 = self.hash_message(msg2)

        # 攻击者恢复k和两个私钥
        s_diff_inv = self.mod_inv((s1 - s2) % self.n, self.n)
        recovered_k = ((e1 - e2) * s_diff_inv) % self.n
        r_inv = self.mod_inv(r1, self.n)
        recovered_d1 = (r_inv * (recovered_k * s1 - e1)) % self.n
        recovered_d2 = (r_inv * (recovered_k * s2 - e2)) % self.n

        print(f"真实私钥 d1 = {d1}, d2 = {d2}")
        print(f"恢复的私钥 d1' = {recovered_d1}, d2' = {recovered_d2}")
        print(f"验证结果: {'成功' if d1 == recovered_d1 and d2 == recovered_d2 else '失败'}")

    def demonstrate_mixed_signatures(self):
        """场景4：混合签名算法导致私钥泄露"""
        print("\n=== 场景4：混合签名算法导致私钥泄露 ===")
        d = 3  # 真实私钥
        k = 2  # 临时密钥
        message = "test_message"

        # 同一私钥和k用于ECDSA和Schnorr签名
        ecdsa_r, ecdsa_s = self.ecdsa_sign(d, message, k)
        schnorr_R, schnorr_s, schnorr_e = self.schnorr_sign(d, message, k)
        e = self.hash_message(message)

        # 攻击者利用两种签名恢复私钥
        denominator = (ecdsa_r + schnorr_e * ecdsa_s) % self.n
        denom_inv = self.mod_inv(denominator, self.n)
        recovered_d = ((schnorr_s * ecdsa_s - e) * denom_inv) % self.n

        print(f"真实私钥 d = {d}")
        print(f"恢复的私钥 d' = {recovered_d}")
        print(f"验证结果: {'成功' if d == recovered_d else '失败'}")


if __name__ == '__main__':
    demo = SignatureMisuseDemo(
        a=5, b=7, p=9,  # 曲线参数
        G=[5, 1],  # 基点
        n=11  # 基点阶数
    )

    demo.demonstrate_k_leakage()
    demo.demonstrate_k_reuse()
    demo.demonstrate_shared_k()

    demo.demonstrate_mixed_signatures()
