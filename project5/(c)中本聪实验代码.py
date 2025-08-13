import math
import random
import hashlib


class EllipticCurveDSA:
    def __init__(self, a, b, prime, base_point, order):
        """
        初始化椭圆曲线参数
        :param a: 曲线参数a
        :param b: 曲线参数b
        :param prime: 有限域素数
        :param base_point: 基点G
        :param order: 基点的阶n
        """
        self.curve_a = a
        self.curve_b = b
        self.field_prime = prime
        self.base_point = base_point
        self.point_order = order

    def compute_inverse(self, value, modulus):
        """计算模逆元"""
        if math.gcd(value, modulus) != 1:
            return None
        return pow(value, -1, modulus)

    def point_addition(self, point1, point2):
        """椭圆曲线点加运算"""
        if not point1:
            return point2
        if not point2:
            return point1

        x1, y1 = point1
        x2, y2 = point2

        # 处理不同点相加
        if x1 != x2:
            delta_x = (x1 - x2) % self.field_prime
            inv_delta = self.compute_inverse(delta_x, self.field_prime)
            if not inv_delta:
                return None  # 无穷远点
            slope = ((y1 - y2) * inv_delta) % self.field_prime
        else:
            # 处理点加倍
            inv_denominator = self.compute_inverse(2 * y1, self.field_prime)
            slope = ((3 * x1 ** 2 + self.curve_a) * inv_denominator) % self.field_prime

        x3 = (slope ** 2 - x1 - x2) % self.field_prime
        y3 = (slope * (x1 - x3) - y1) % self.field_prime

        return (x3, y3)

    def scalar_multiplication(self, scalar, point):
        """椭圆曲线标量乘法"""
        if scalar == 0:
            return None
        result = None
        current = point

        while scalar > 0:
            if scalar % 2 == 1:
                result = self.point_addition(result, current) if result else current
            current = self.point_addition(current, current)
            scalar = scalar // 2
        return result

    def generate_hash(self, message):
        """生成消息哈希"""
        hash_bytes = hashlib.sha256(message.encode()).digest()
        return int.from_bytes(hash_bytes, 'big') % self.point_order

    def generate_signature(self, private_key, message, ephemeral_key):
        """生成ECDSA签名"""
        R = self.scalar_multiplication(ephemeral_key, self.base_point)
        if not R:
            raise ValueError("无效的临时密钥")

        r = R[0] % self.point_order
        e = self.generate_hash(message)
        k_inv = self.compute_inverse(ephemeral_key, self.point_order)

        if not k_inv:
            raise ValueError("临时密钥无效")

        s = (k_inv * (e + private_key * r)) % self.point_order
        return (r, s)

    def verify_signature(self, message, signature, public_key):
        """验证ECDSA签名"""
        r, s = signature
        if not (0 < r < self.point_order and 0 < s < self.point_order):
            return False

        e = self.generate_hash(message)
        w = self.compute_inverse(s, self.point_order)
        if not w:
            return False

        u1 = (e * w) % self.point_order
        u2 = (r * w) % self.point_order

        point1 = self.scalar_multiplication(u1, self.base_point)
        point2 = self.scalar_multiplication(u2, public_key)

        verification_point = self.point_addition(point1, point2)
        return verification_point and verification_point[0] % self.point_order == r

    def forge_signature(self, public_key):
        """实施无消息伪造签名(Satoshi方法)"""
        u = random.randint(1, self.point_order - 1)
        v = random.randint(1, self.point_order - 1)

        R = self.point_addition(
            self.scalar_multiplication(u, self.base_point),
            self.scalar_multiplication(v, public_key)
        )

        if not R:
            return None

        r = R[0]
        v_inv = self.compute_inverse(v, self.point_order)
        if not v_inv:
            return None

        forged_e = (r * u * v_inv) % self.point_order
        forged_s = (r * v_inv) % self.point_order

        return (r, forged_s, forged_e)


# 测试用例
if __name__ == "__main__":
    # 初始化曲线参数 (使用小参数仅用于演示)
    curve = EllipticCurveDSA(
        a=2, b=3,
        prime=17,
        base_point=(6, 9),
        order=19
    )

    private_key = 5
    ephemeral_key = 3
    public_key = curve.scalar_multiplication(private_key, curve.base_point)

    message1 = "zxj761"
    message2 = "SDU2025"

    # 正常签名验证流程
    signature = curve.generate_signature(private_key, message1, ephemeral_key)
    print(f"签名结果: {signature}")
    print(f"验证结果: {curve.verify_signature(message1, signature, public_key)}")

    # 伪造签名演示
    forged = curve.forge_signature(public_key)
    if forged:
        r, s, e = forged
        print(f"\n伪造的签名(r,s): ({r}, {s})")
        print(f"对应的伪造消息哈希e: {e}")
        print("验证伪造签名:", curve.verify_signature(str(e), (r, s), public_key))