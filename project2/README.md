# 数字水印系统实验报告

## 1. 实验目标
实现基于DCT变换的不可见水印系统，测试抗攻击能力

## 2. 核心原理
### 2.1 DCT变换公式
```math
F(u,v) = \sum_{x=0}^{7}\sum_{y=0}^{7}f(x,y)\cdot\cos\frac{(2x+1)u\pi}{16}\cdot\cos\frac{(2y+1)v\pi}{16}
```
### 2.2 水印嵌入位置
选择中频系数(5,2)位置进行修改：
```math
F'(5,2) = F(5,2) + \alpha \cdot (2w_{ij}-1) \cdot F(0,0)
```

## 3. 实验步骤

### 3.1 代码结构
```python
class DCTWatermark:
    ├── embed()          # 嵌入水印
    ├── extract()        # 提取水印 
    └── _get_dct_blocks() # DCT分块处理
```
## 3.2 操作流程

1. **准备测试图像**：
   - 宿主图像：`lena.jpg`  
   - 水印图像：`watermark.png`（64×64黑白二值图）

2. **执行命令**：
```bash
python watermark_system.py
```

## 4. 实验结果
