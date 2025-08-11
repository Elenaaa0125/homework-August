# SM2椭圆曲线密码算法实现与优化实验报告

## 实验目的
1. 实现国密SM2椭圆曲线数字签名算法的基础版本
2. 探索并实现两种典型优化方法（预计算/Jacobian坐标）
3. 分析比较不同实现的性能差异
4. 验证算法实现的正确性和可靠性

## 实验环境
| 项目         | 配置说明                  |
|--------------|-------------------------|
| 操作系统      | Ubuntu 20.04 LTS        |
| Python版本    | Python 3.8.10           |
| CPU          | Intel i7-10750H 2.6GHz  |
| 内存         | 16GB DDR4               |
| 测试数据集    | 随机生成100组密钥对和消息 |

## 算法实现

### 基础实现（SM2Base）
```python
class SM2Base:
    # 国标推荐参数（256位素数域）
    p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
    a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
    b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
    n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
    
    def point_mul(self, k: int, P: Tuple[int, int]) -> Tuple[int, int]:
        # 二进制展开法实现标量乘法
        R = (0, 0)
        for i in reversed(range(k.bit_length())):
            R = self.point_add(R, R)
            if (k >> i) & 1:
                R = self.point_add(R, P)
        return R

  ```

### 优化版本1：预计算加速（SM2Optimized1）

预计算是一种空间换时间的优化策略，通过预先计算并存储一些频繁使用的中间结果，来减少实时计算时的运算量。
```python
class SM2Optimized1(SM2Base):
    def __init__(self):
        self.precomputed = {}  # 预计算表
        self._precompute()
    
    def _precompute(self):
        # 预计算2^i * G (0 ≤ i < 256)
        P = self.G
        for i in range(256):
            self.precomputed[i] = P
            P = self.point_add(P, P)

  ```


### 优化版本2：Jacobian坐标（SM2Optimized2）
Jacobian坐标是射影坐标的一种，通过增加一个坐标维度(z坐标)来表示二维仿射平面上的点，可以避免模逆运算(模逆运算在密码学中计算代价很高)。
```python
class SM2Optimized2(SM2Base):
    def jacobian_add(self, P: Tuple[int,int,int], Q: Tuple[int,int,int]):
        # Jacobian坐标下的点加运算
        if P[2] == 0: return Q
        if Q[2] == 0: return P
        
        U1 = (P[0] * Q[2]**2) % self.p
        U2 = (Q[0] * P[2]**2) % self.p
        S1 = (P[1] * Q[2]**3) % self.p
        S2 = (Q[1] * P[2]**3) % self.p
        
        if U1 == U2:
            return self.jacobian_double(P)
        
        H = U2 - U1
        R = S2 - S1
        x3 = (R**2 - H**3 - 2*U1*H**2) % self.p
        y3 = (R*(U1*H**2 - x3) - S1*H**3) % self.p
        z3 = (H*P[2]*Q[2]) % self.p
        return (x3, y3, z3)

  ```
## 实验过程

### 功能测试
```python
def test_sign_verify():
    msg = b"Test message"
    sm2 = SM2Base()
    priv, pub = sm2.generate_keypair()
    
    # 签名验证测试
    sig = sm2.sign(msg, priv)
    assert sm2.verify(msg, sig, pub), "Base验证失败"
    
    # 篡改检测测试
    tampered_msg = msg + b"x"
    assert not sm2.verify(tampered_msg, sig, pub), "篡改检测失败"
```


### 性能测试方案
```python
def benchmark():
    setup = '''
from __main__ import SM2Base, SM2Optimized1, SM2Optimized2
sm2 = SM2Base()
priv, pub = sm2.generate_keypair()
    '''
    
    stmt_base = 'sm2.point_mul(priv, sm2.G)'
    stmt_opt1 = 'SM2Optimized1().point_mul(priv, sm2.G)'
    stmt_opt2 = 'SM2Optimized2().point_mul(priv, sm2.G)'
    
    # 使用timeit进行基准测试
    t_base = timeit.timeit(stmt_base, setup, number=1000)
    t_opt1 = timeit.timeit(stmt_opt1, setup, number=1000)
    t_opt2 = timeit.timeit(stmt_opt2, setup, number=1000)
```
## 实验结果

![测试结果对比图](屏幕截图%202025-08-11%20155124.png) 
