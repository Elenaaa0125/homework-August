#include <iostream>
#include <vector>
#include <cstring>
#include <algorithm>
#include <iomanip>
#include <string>
#include <random>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3算法实现
namespace SM3 {
    static const uint32_t IV[8] = {
        0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
        0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
    };

    static const uint32_t T[64] = {
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x79cc4519, 0x79cc4519, 0x79cc4519, 0x79cc4519,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a,
        0x7a879d8a, 0x7a879d8a, 0x7a879d8a, 0x7a879d8a
    };

    uint32_t P0(uint32_t x) { return x ^ ROTL32(x, 9) ^ ROTL32(x, 17); }
    uint32_t P1(uint32_t x) { return x ^ ROTL32(x, 15) ^ ROTL32(x, 23); }

    void message_schedule(const uint8_t* message, uint32_t* W) {
        for (int i = 0; i < 16; i++) {
            W[i] = (message[i * 4] << 24) | (message[i * 4 + 1] << 16)
                | (message[i * 4 + 2] << 8) | message[i * 4 + 3];
        }
        for (int i = 16; i < 68; i++) {
            W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL32(W[i - 3], 15))
                ^ ROTL32(W[i - 13], 7) ^ W[i - 6];
        }
    }

    void compression_function(uint32_t* V, const uint32_t* W) {
        uint32_t W1[64];
        for (int j = 0; j < 64; j++) {
            W1[j] = W[j] ^ W[j + 4];
        }

        uint32_t A = V[0], B = V[1], C = V[2], D = V[3];
        uint32_t E = V[4], F = V[5], G = V[6], H = V[7];

        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(T[j], j), 7);
            uint32_t SS2 = SS1 ^ ROTL32(A, 12);
            uint32_t TT1 = (A ^ B ^ C) + D + SS2 + W1[j];
            uint32_t TT2 = (E ^ F ^ G) + H + SS1 + W[j];

            D = C;
            C = ROTL32(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = ROTL32(F, 19);
            F = E;
            E = P0(TT2);
        }

        V[0] ^= A; V[1] ^= B; V[2] ^= C; V[3] ^= D;
        V[4] ^= E; V[5] ^= F; V[6] ^= G; V[7] ^= H;
    }

    void hash(const uint8_t* input, size_t len, uint8_t* output) {
        uint32_t V[8];
        memcpy(V, IV, sizeof(IV));

        size_t block_count = (len + 8 + 63) / 64;
        std::vector<uint8_t> padded_input(block_count * 64, 0);
        memcpy(padded_input.data(), input, len);

        padded_input[len] = 0x80;
        uint64_t bit_len = len * 8;
        for (int i = 0; i < 8; i++) {
            padded_input[block_count * 64 - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
        }

        for (size_t i = 0; i < block_count; i++) {
            uint32_t W[68];
            message_schedule(padded_input.data() + i * 64, W);
            compression_function(V, W);
        }

        for (int i = 0; i < 8; i++) {
            output[i * 4] = (V[i] >> 24) & 0xff;
            output[i * 4 + 1] = (V[i] >> 16) & 0xff;
            output[i * 4 + 2] = (V[i] >> 8) & 0xff;
            output[i * 4 + 3] = V[i] & 0xff;
        }
    }
}

// Merkle树实现
class MerkleTree {
private:
    std::vector<std::vector<std::vector<uint8_t>>> tree;
    size_t leaf_count;

    static std::vector<uint8_t> hash_concatenation(const std::vector<uint8_t>& a, const std::vector<uint8_t>& b) {
        std::vector<uint8_t> concatenated(a);
        concatenated.insert(concatenated.end(), b.begin(), b.end());

        std::vector<uint8_t> result(32);
        SM3::hash(concatenated.data(), concatenated.size(), result.data());
        return result;
    }

public:
    MerkleTree(const std::vector<std::vector<uint8_t>>& leaves) : leaf_count(leaves.size()) {
        if (leaf_count == 0) return;

        // 构建叶子层
        tree.push_back(leaves);

        // 构建中间层
        while (tree.back().size() > 1) {
            const auto& current_level = tree.back();
            std::vector<std::vector<uint8_t>> next_level;

            for (size_t i = 0; i < current_level.size(); i += 2) {
                if (i + 1 < current_level.size()) {
                    next_level.push_back(hash_concatenation(current_level[i], current_level[i + 1]));
                }
                else {
                    // 奇数个节点时复制最后一个节点
                    next_level.push_back(hash_concatenation(current_level[i], current_level[i]));
                }
            }

            tree.push_back(next_level);
        }
    }

    const std::vector<uint8_t>& get_root() const {
        if (tree.empty() || tree.back().empty()) {
            static std::vector<uint8_t> empty_hash(32, 0);
            return empty_hash;
        }
        return tree.back()[0];
    }

    // 获取存在性证明路径
    std::vector<std::pair<std::vector<uint8_t>, bool>> get_inclusion_proof(size_t index) const {
        std::vector<std::pair<std::vector<uint8_t>, bool>> proof;

        if (index >= leaf_count) {
            std::cerr << "Error: Index out of range (" << index << " >= " << leaf_count << ")\n";
            return proof;
        }

        for (size_t level = 0; level < tree.size() - 1; ++level) {
            bool is_right = (index % 2);
            size_t sibling_index = is_right ? index - 1 : index + 1;

            // 确保兄弟节点存在
            if (sibling_index >= tree[level].size()) {
                sibling_index = index; // 处理奇数情况
            }

            proof.push_back(std::make_pair(tree[level][sibling_index], is_right));
            index /= 2;
        }

        return proof;
    }

    // 验证存在性证明
    static bool verify_inclusion(const std::vector<uint8_t>& leaf,
        const std::vector<uint8_t>& root,
        const std::vector<std::pair<std::vector<uint8_t>, bool>>& proof) {
        std::vector<uint8_t> current_hash = leaf;

        for (size_t i = 0; i < proof.size(); ++i) {
            const std::vector<uint8_t>& sibling_hash = proof[i].first;
            bool is_right = proof[i].second;

            if (is_right) {
                current_hash = hash_concatenation(sibling_hash, current_hash);
            }
            else {
                current_hash = hash_concatenation(current_hash, sibling_hash);
            }
        }

        return current_hash == root;
    }
};

// 生成随机叶子节点
std::vector<std::vector<uint8_t>> generate_random_leaves(size_t count) {
    std::vector<std::vector<uint8_t>> leaves;
    leaves.reserve(count);

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < count; ++i) {
        std::vector<uint8_t> leaf(32);
        for (auto& byte : leaf) {
            byte = static_cast<uint8_t>(dis(gen));
        }
        leaves.push_back(leaf);
    }

    return leaves;
}

// 将哈希值转换为十六进制字符串
std::string hash_to_hex(const std::vector<uint8_t>& hash) {
    std::string hex;
    hex.reserve(hash.size() * 2);
    for (uint8_t byte : hash) {
        char buf[3];
        snprintf(buf, sizeof(buf), "%02x", byte);
        hex += buf;
    }
    return hex;
}

int main() {
    try {
        const size_t LEAF_COUNT = 100000; // 10万叶子节点

        // 1. 生成随机叶子节点
        std::cout << "Generating " << LEAF_COUNT << " random leaves..." << std::endl;
        auto leaves = generate_random_leaves(LEAF_COUNT);

        // 2. 构建Merkle树
        std::cout << "Building Merkle tree..." << std::endl;
        MerkleTree tree(leaves);
        auto root = tree.get_root();
        std::cout << "Merkle root: " << hash_to_hex(root) << std::endl;

        // 3. 测试存在性证明
        size_t test_index = 12345; // 测试第12345个叶子节点
        if (test_index >= leaves.size()) {
            std::cerr << "Error: Test index out of range\n";
            return 1;
        }

        std::cout << "\nTesting inclusion proof for leaf #" << test_index << "..." << std::endl;
        auto inclusion_proof = tree.get_inclusion_proof(test_index);
        bool is_valid = MerkleTree::verify_inclusion(leaves[test_index], root, inclusion_proof);
        std::cout << "Inclusion proof is " << (is_valid ? "valid" : "invalid") << std::endl;

    }
    catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}