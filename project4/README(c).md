# SM3哈希算法与Merkle树实验报告

## 一. 实验目的
1. 基于SM3构建Merkle树结构
2. 验证Merkle树的包含性证明功能
3. 测试大规模数据(10万叶子节点)下的Merkle树性能

## 二. 实验环境
- 操作系统: Windows/Linux/macOS
- 编译器: 支持C++11标准的编译器(g++/clang++)
- 硬件配置: 建议8GB以上内存(处理10万叶子节点)

## 三. 算法实现

### 3.1 SM3哈希算法
```cpp
// 关键实现代码
#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

namespace SM3 {
    // 初始化向量IV
    static const uint32_t IV[8] = {...};
    
    // 常量T值
    static const uint32_t T[64] = {...};
    
    // 置换函数
    uint32_t P0(uint32_t x) { return x ^ ROTL32(x, 9) ^ ROTL32(x, 17); }
    uint32_t P1(uint32_t x) { return x ^ ROTL32(x, 15) ^ ROTL32(x, 23); }
    
    // 消息扩展
    void message_schedule(const uint8_t* message, uint32_t* W) {...}
    
    // 压缩函数
    void compression_function(uint32_t* V, const uint32_t* W) {...}
    
    // 哈希主函数
    void hash(const uint8_t* input, size_t len, uint8_t* output) {...}
}
```

### 3.2 Merkle树的构建
```cpp
class MerkleTree {
private:
    std::vector<std::vector<std::vector<uint8_t>>> tree;
    size_t leaf_count;
    
    // 哈希连接函数
    static std::vector<uint8_t> hash_concatenation(...) {...}
    
public:
    // 构造函数
    MerkleTree(const std::vector<std::vector<uint8_t>>& leaves) {...}
    
    // 获取根哈希
    const std::vector<uint8_t>& get_root() const {...}
    
    // 获取包含性证明
    std::vector<std::pair<std::vector<uint8_t>, bool>> get_inclusion_proof(...) {...}
    
    // 验证包含性证明
    static bool verify_inclusion(...) {...}
};
```

## 四、Merkle证明过程详解

### 4.1 包含性证明生成过程

#### 算法步骤：
1. **输入**：叶子节点索引`index`
2. **初始化**：空证明列表`proof = []`
3. **层级遍历**：
   ```python
   current_index = index
   for level in 0 to tree_height-1:
       # 确定兄弟节点位置
       if current_index % 2 == 1:  # 当前是右节点
           sibling_index = current_index - 1
           is_right = False
       else:                       # 当前是左节点
           sibling_index = current_index + 1 
           is_right = True
       
       # 获取兄弟节点哈希
       sibling_hash = tree[level][sibling_index]
       proof.append((sibling_hash, is_right))
       
       # 上移到父层
       current_index = current_index // 2

   ```

   ### 4.2 实验结果
   ![测试结果对比图](屏幕截图%202025-08-11%20114111.png) 
