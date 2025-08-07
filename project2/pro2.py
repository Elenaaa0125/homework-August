import cv2
import numpy as np
from matplotlib import pyplot as plt
import os
from skimage.util import random_noise
from PIL import Image


class DCTWatermark:
    def __init__(self, strength=0.1):
        self.strength = max(0.01, min(strength, 0.3))  # 限制强度范围在0.01-0.3之间

    def _get_dct_blocks(self, img):
        """将图像分割为8x8块并进行DCT变换"""
        h, w = img.shape
        blocks = []
        for i in range(0, h, 8):
            for j in range(0, w, 8):
                block = img[i:i + 8, j:j + 8]
                if block.shape == (8, 8):
                    dct_block = cv2.dct(np.float32(block))
                    blocks.append((i, j, dct_block))
        return blocks

    def _reconstruct_from_blocks(self, blocks, shape):
        """从DCT块重建图像"""
        img = np.zeros(shape, dtype=np.float32)
        for i, j, dct_block in blocks:
            idct_block = cv2.idct(dct_block)
            img[i:i + 8, j:j + 8] = idct_block
        return img

    def embed(self, host_img, watermark_img, output_path=None):
        """
        嵌入水印
        :param host_img: 宿主图像路径或numpy数组
        :param watermark_img: 水印图像路径或numpy数组
        :param output_path: 输出路径(可选)
        :return: 含水印图像
        """
        # 读取图像
        if isinstance(host_img, str):
            host = cv2.imread(host_img, cv2.IMREAD_GRAYSCALE)
        else:
            host = cv2.cvtColor(host_img, cv2.COLOR_BGR2GRAY) if len(host_img.shape) == 3 else host_img

        if isinstance(watermark_img, str):
            watermark = cv2.imread(watermark_img, cv2.IMREAD_GRAYSCALE)
        else:
            watermark = cv2.cvtColor(watermark_img, cv2.COLOR_BGR2GRAY) if len(
                watermark_img.shape) == 3 else watermark_img

        # 检查图像是否加载成功
        if host is None:
            raise ValueError("无法加载宿主图像，请检查路径")
        if watermark is None:
            raise ValueError("无法加载水印图像，请检查路径")

        # 调整水印大小并二值化
        watermark = cv2.resize(watermark, (host.shape[1] // 8, host.shape[0] // 8))
        _, watermark = cv2.threshold(watermark, 127, 1, cv2.THRESH_BINARY)

        # 分块DCT变换
        blocks = self._get_dct_blocks(host)

        # 在DCT中频系数嵌入水印（添加数值限制）
        watermark_flat = watermark.flatten()
        for idx, (i, j, block) in enumerate(blocks):
            if idx >= len(watermark_flat):
                break
            delta = self.strength * (2 * watermark_flat[idx] - 1) * block[0, 0]
            block[5, 2] = np.clip(block[5, 2] + delta, -32768, 32767)  # 限制在int16范围内

        # 重建图像
        watermarked = self._reconstruct_from_blocks(blocks, host.shape)
        watermarked = np.clip(watermarked, 0, 255).astype(np.uint8)

        if output_path:
            cv2.imwrite(output_path, watermarked)

        return watermarked

    def extract(self, watermarked_img, original_img=None, watermark_shape=None):
        """
        提取水印
        :param watermarked_img: 含水印图像（numpy数组或路径）
        :param original_img: 原始图像(非盲检测时需要)
        :param watermark_shape: 水印图像形状(h,w)
        :return: 提取的水印
        """
        # 统一转换为numpy数组
        if isinstance(watermarked_img, str):
            wm_img = cv2.imread(watermarked_img, cv2.IMREAD_GRAYSCALE)
        elif isinstance(watermarked_img, Image.Image):  # 处理PIL图像
            wm_img = np.array(watermarked_img)
        else:
            wm_img = cv2.cvtColor(watermarked_img, cv2.COLOR_BGR2GRAY) if len(
                watermarked_img.shape) == 3 else watermarked_img

        if original_img is not None:  # 非盲检测
            if isinstance(original_img, str):
                org_img = cv2.imread(original_img, cv2.IMREAD_GRAYSCALE)
            elif isinstance(original_img, Image.Image):
                org_img = np.array(original_img)
            else:
                org_img = cv2.cvtColor(original_img, cv2.COLOR_BGR2GRAY) if len(
                    original_img.shape) == 3 else original_img
            diff = wm_img.astype(np.float32) - org_img.astype(np.float32)
        else:  # 盲检测
            diff = wm_img.astype(np.float32)

        blocks = self._get_dct_blocks(diff)
        watermark = []

        for _, _, block in blocks:
            # 从相同位置提取水印
            value = block[5, 2] / (self.strength * block[0, 0]) if block[0, 0] != 0 else 0
            watermark.append(1 if value > 0 else 0)

        if watermark_shape:
            watermark = np.array(watermark[:watermark_shape[0] * watermark_shape[1]])
            watermark = watermark.reshape(watermark_shape)
        else:
            watermark = np.array(watermark)

        return (watermark * 255).astype(np.uint8)


def robustness_test(watermarker, original_img, watermark_img):
    """测试水印鲁棒性（已修复PIL/OpenCV类型转换问题）"""
    # 嵌入水印（确保是numpy数组）
    wm_img = watermarker.embed(original_img, watermark_img)

    attacks = {
        '旋转10度': lambda x: Image.fromarray(x).rotate(10).convert('L'),
        '缩放0.8倍': lambda x: cv2.resize(x, None, fx=0.8, fy=0.8),
        '裁剪20%': lambda x: x[int(0.1 * x.shape[0]):int(0.9 * x.shape[0]),
                             int(0.1 * x.shape[1]):int(0.9 * x.shape[1])],
        '高斯噪声': lambda x: (random_noise(x, mode='gaussian', var=0.01) * 255).astype(np.uint8),
        '对比度调整': lambda x: cv2.convertScaleAbs(x, alpha=1.5, beta=0),
        'JPEG压缩': lambda x: cv2.imdecode(cv2.imencode('.jpg', x, [int(cv2.IMWRITE_JPEG_QUALITY), 50])[1], -1)
    }

    results = {}
    for name, attack in attacks.items():
        try:
            attacked = attack(wm_img)
            # 统一转换为numpy数组
            if isinstance(attacked, Image.Image):
                attacked = np.array(attacked)

            extracted = watermarker.extract(attacked, watermark_shape=(64, 64))

            # 计算相似度
            orig_wm = cv2.resize(cv2.imread(watermark_img, 0), (64, 64)) > 127
            sim = np.mean((extracted > 127) == orig_wm)
            results[name] = sim

            # 可视化
            plt.figure(figsize=(12, 4))
            plt.subplot(131), plt.imshow(wm_img, cmap='gray'), plt.title('含水印图像')
            plt.subplot(132), plt.imshow(attacked, cmap='gray'), plt.title(f'攻击: {name}')
            plt.subplot(133), plt.imshow(extracted, cmap='gray'), plt.title(f'提取水印(相似度:{sim:.2f})')
            plt.show()

        except Exception as e:
            print(f"攻击测试 {name} 失败: {str(e)}")
            results[name] = 0

    return results


# ====================== 使用示例 ======================
if __name__ == '__main__':
    # 初始化水印系统
    watermarker = DCTWatermark(strength=0.25)

    watermark = np.zeros((64, 64), dtype=np.uint8)
    watermark[20:44, 20:44] = 255  # 中心白色方块
    cv2.imwrite(r'D:\pythonProject4\watermark_square.png', watermark)

    # 嵌入水印
    host_img = r'D:\pythonProject4\pexels-clarissa-roley-139936449-33334417.jpg'
    watermark_img = r'D:\pythonProject4\watermark_square.png'  # 二值水印图片(建议64x64左右)
    watermarked = watermarker.embed(host_img, watermark_img, r'D:\pythonProject4\watermarked_lena.jpg')

    # 提取水印
    extracted = watermarker.extract(watermarked, host_img, (64, 64))
    cv2.imwrite(r'D:\pythonProject4\extracted_watermark.jpg', extracted)

    # 鲁棒性测试
    test_results = robustness_test(watermarker, host_img, watermark_img)
    print("\n鲁棒性测试结果:")
    for attack, score in test_results.items():
        print(f"{attack}: {score:.2%}")