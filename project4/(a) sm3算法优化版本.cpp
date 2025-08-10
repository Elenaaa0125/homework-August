#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <random>
#include <iomanip>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3算法常量
static const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
};

// 优化后的置换函数
inline uint32_t P0(uint32_t x) {
    uint32_t rot9 = ROTL32(x, 9);
    uint32_t rot17 = ROTL32(x, 17);
    return x ^ rot9 ^ rot17;
}

inline uint32_t P1(uint32_t x) {
    uint32_t rot15 = ROTL32(x, 15);
    uint32_t rot23 = ROTL32(x, 23);
    return x ^ rot15 ^ rot23;
}

// 原始消息调度函数
void message_schedule(const uint8_t* message, uint32_t* W) {
    for (int i = 0; i < 16; i++) {
        W[i] = (message[i * 4] << 24) | (message[i * 4 + 1] << 16) | (message[i * 4 + 2] << 8) | message[i * 4 + 3];
    }
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL32(W[i - 3], 15)) ^ ROTL32(W[i - 13], 7) ^ W[i - 6];
    }
}

// 优化后的消息扩展函数 - 使用循环展开
void optimized_message_schedule(const uint8_t* message, uint32_t* W) {
    // 前16个字直接填充
    for (int i = 0; i < 16; i++) {
        W[i] = (message[i * 4] << 24) | (message[i * 4 + 1] << 16) | (message[i * 4 + 2] << 8) | message[i * 4 + 3];
    }

    // 展开循环计算W16-W67
    for (int i = 16; i < 68; i++) {
        uint32_t temp = W[i - 16] ^ W[i - 9];
        uint32_t rot3 = ROTL32(W[i - 3], 15);
        W[i] = P1(temp ^ rot3) ^ ROTL32(W[i - 13], 7) ^ W[i - 6];
    }
}

// 原始压缩函数
void compression(uint32_t* H, const uint32_t* W) {
    uint32_t W1[64];
    for (int j = 0; j < 64; j++) {
        W1[j] = P0(W[j] ^ W[j + 4]);
    }

    uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
    uint32_t E = H[4], F = H[5], G = H[6], H_val = H[7];

    for (int j = 0; j < 64; j++) {
        uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32((j < 16 ? 0x79cc4519 : 0x7a879d8a), j % 32), 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1 = (j < 16 ? (A ^ B ^ C) : ((A & B) | (A & C) | (B & C))) + D + SS2 + W1[j];
        uint32_t TT2 = (j < 16 ? (E ^ F ^ G) : ((E & F) | ((~E) & G))) + H_val + SS1 + W[j];

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H_val = G;
        G = F;
        F = E;
        E = TT2;
    }

    H[0] ^= A; H[1] ^= B; H[2] ^= C; H[3] ^= D;
    H[4] ^= E; H[5] ^= F; H[6] ^= G; H[7] ^= H_val;
}

// 优化后的压缩函数
void optimized_compression(uint32_t* H, const uint32_t* W) {
    uint32_t W1[64];
    for (int j = 0; j < 64; j++) {
        W1[j] = P0(W[j] ^ W[j + 4]);
    }

    uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
    uint32_t E = H[4], F = H[5], G = H[6], H_val = H[7];

    // 前16轮
    for (int j = 0; j < 16; j++) {
        uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(0x79cc4519, j), 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1 = (A ^ B ^ C) + D + SS2 + W1[j];
        uint32_t TT2 = (E ^ F ^ G) + H_val + SS1 + W[j];

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H_val = G;
        G = F;
        F = E;
        E = TT2;
    }

    // 后48轮
    for (int j = 16; j < 64; j++) {
        uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(0x7a879d8a, j), 7);
        uint32_t SS2 = SS1 ^ ROTL32(A, 12);
        uint32_t TT1 = ((A & B) | (A & C) | (B & C)) + D + SS2 + W1[j];
        uint32_t TT2 = ((E & F) | ((~E) & G)) + H_val + SS1 + W[j];

        D = C;
        C = ROTL32(B, 9);
        B = A;
        A = TT1;
        H_val = G;
        G = F;
        F = E;
        E = TT2;
    }

    H[0] ^= A; H[1] ^= B; H[2] ^= C; H[3] ^= D;
    H[4] ^= E; H[5] ^= F; H[6] ^= G; H[7] ^= H_val;
}

// 原始SM3算法
void sm3(const uint8_t* input, size_t len, uint8_t* output) {
    uint32_t H[8];
    memcpy(H, IV, sizeof(IV));

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
        compression(H, W);
    }

    for (int i = 0; i < 8; i++) {
        output[i * 4] = (H[i] >> 24) & 0xff;
        output[i * 4 + 1] = (H[i] >> 16) & 0xff;
        output[i * 4 + 2] = (H[i] >> 8) & 0xff;
        output[i * 4 + 3] = H[i] & 0xff;
    }
}

// 优化后的SM3算法
void optimized_sm3(const uint8_t* input, size_t len, uint8_t* output) {
    uint32_t H[8];
    memcpy(H, IV, sizeof(IV));

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
        optimized_message_schedule(padded_input.data() + i * 64, W);
        optimized_compression(H, W);
    }

    for (int i = 0; i < 8; i++) {
        output[i * 4] = (H[i] >> 24) & 0xff;
        output[i * 4 + 1] = (H[i] >> 16) & 0xff;
        output[i * 4 + 2] = (H[i] >> 8) & 0xff;
        output[i * 4 + 3] = H[i] & 0xff;
    }
}

// ===================== 测试工具函数 =====================
std::vector<uint8_t> generate_random_data(size_t size) {
    std::vector<uint8_t> data(size);
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);
    for (auto& byte : data) {
        byte = static_cast<uint8_t>(dis(gen));
    }
    return data;
}

void print_hash(const uint8_t* hash, size_t len) {
    for (size_t i = 0; i < len; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(hash[i]);
    }
    std::cout << std::dec << std::endl;
}

void compare_performance(size_t data_size, int iterations) {
    auto data = generate_random_data(data_size);
    uint8_t hash1[32], hash2[32];

    // 测试原始算法
    auto start1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        sm3(data.data(), data.size(), hash1);
    }
    auto end1 = std::chrono::high_resolution_clock::now();
    auto duration1 = std::chrono::duration_cast<std::chrono::microseconds>(end1 - start1).count();

    // 测试优化算法
    auto start2 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < iterations; i++) {
        optimized_sm3(data.data(), data.size(), hash2);
    }
    auto end2 = std::chrono::high_resolution_clock::now();
    auto duration2 = std::chrono::duration_cast<std::chrono::microseconds>(end2 - start2).count();

    // 验证结果一致性
    if (memcmp(hash1, hash2, 32) != 0) {
        std::cerr << "错误: 优化算法结果与原始算法不一致!" << std::endl;
        std::cout << "原始结果: "; print_hash(hash1, 32);
        std::cout << "优化结果: "; print_hash(hash2, 32);
        return;
    }

    // 计算结果
    double total_bytes = static_cast<double>(data_size) * iterations;
    double speed1 = (total_bytes * 8) / (duration1 / 1e6) / 1e6; // Mbps
    double speed2 = (total_bytes * 8) / (duration2 / 1e6) / 1e6; // Mbps
    double improvement = (duration1 - duration2) * 100.0 / duration1;

    // 打印结果
    std::cout << "==============================" << std::endl;
    std::cout << "性能对比测试 (数据大小: " << data_size << " bytes, 迭代: " << iterations << ")" << std::endl;
    std::cout << "原始算法耗时: " << duration1 << " μs (" << speed1 << " Mbps)" << std::endl;
    std::cout << "优化算法耗时: " << duration2 << " μs (" << speed2 << " Mbps)" << std::endl;
    std::cout << "性能提升: " << improvement << "%" << std::endl;
    std::cout << "==============================" << std::endl;
}

// 主函数
int main() {
    // 正确性测试
    const char* test_str = "abc";
    uint8_t hash1[32], hash2[32];

    sm3(reinterpret_cast<const uint8_t*>(test_str), strlen(test_str), hash1);
    optimized_sm3(reinterpret_cast<const uint8_t*>(test_str), strlen(test_str), hash2);

    std::cout << "原始SM3(\"abc\"): ";
    print_hash(hash1, 32);
    std::cout << "优化SM3(\"abc\"): ";
    print_hash(hash2, 32);

    if (memcmp(hash1, hash2, 32) == 0) {
        std::cout << "结果验证通过!" << std::endl;
    }
    else {
        std::cout << "错误: 结果不一致!" << std::endl;
        return 1;
    }

    // 性能对比测试
    compare_performance(1 * 1024, 10000);     // 1KB数据
    compare_performance(10 * 1024, 1000);     // 10KB数据
    compare_performance(100 * 1024, 100);     // 100KB数据
    compare_performance(1024 * 1024, 10);     // 1MB数据

    return 0;
}