#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <random>
#include <iomanip>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3算法实现
static const uint32_t IV[8] = {
    0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
    0x5a63e28c, 0x2f5f1b22, 0x3b101e6d, 0x9b4e430d
};

uint32_t P0(uint32_t x) { return x ^ ROTL32(x, 9) ^ ROTL32(x, 17); }
uint32_t P1(uint32_t x) { return x ^ ROTL32(x, 15) ^ ROTL32(x, 23); }

void message_schedule(const uint8_t* message, uint32_t* W) {
    for (int i = 0; i < 16; i++) {
        W[i] = (message[i * 4] << 24) | (message[i * 4 + 1] << 16) | (message[i * 4 + 2] << 8) | message[i * 4 + 3];
    }
    for (int i = 16; i < 68; i++) {
        W[i] = P1(W[i - 16] ^ W[i - 9] ^ ROTL32(W[i - 3], 15)) ^ ROTL32(W[i - 13], 7) ^ W[i - 6];
    }
}

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

        uint32_t W1[64];
        for (int j = 0; j < 64; j++) {
            W1[j] = P0(W[j] ^ W[j + 4]);
        }

        uint32_t A = H[0], B = H[1], C = H[2], D = H[3];
        uint32_t E = H[4], F = H[5], G = H[6], H0 = H[7];

        for (int j = 0; j < 64; j++) {
            uint32_t SS1 = ROTL32(ROTL32(A, 12) + E + ROTL32(0x79cc4519, j % 32), 7);
            uint32_t SS2 = SS1 ^ ROTL32(A, 12);
            uint32_t T = P1(A ^ B ^ C) + D + SS2 + W1[j];

            D = C;
            C = ROTL32(B, 9);
            B = A;
            A = T;
            E = F;
            F = G;
            G = H0;
            H0 = P1(E ^ F ^ G) + H[4] + SS1 + W[j];
        }

        H[0] ^= A; H[1] ^= B; H[2] ^= C; H[3] ^= D;
        H[4] ^= E; H[5] ^= F; H[6] ^= G; H[7] ^= H0;
    }

    for (int i = 0; i < 8; i++) {
        output[i * 4] = (H[i] >> 24) & 0xff;
        output[i * 4 + 1] = (H[i] >> 16) & 0xff;
        output[i * 4 + 2] = (H[i] >> 8) & 0xff;
        output[i * 4 + 3] = H[i] & 0xff;
    }
}

// ===================== 性能测试代码 =====================
// 生成随机测试数据
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

// 测试函数
void performance_test(size_t data_size, int iterations) {
    auto data = generate_random_data(data_size);
    uint8_t hash[32];

    // 预热（避免冷启动误差）
    sm3(data.data(), data.size(), hash);

    // 开始计时
    auto start = std::chrono::high_resolution_clock::now();

    // 多次迭代计算
    for (int i = 0; i < iterations; i++) {
        sm3(data.data(), data.size(), hash);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();

    // 计算结果
    double total_bytes = static_cast<double>(data_size) * iterations;
    double total_seconds = duration / 1e6;
    double speed_mbps = (total_bytes * 8) / (total_seconds * 1e6);

    // 打印结果
    std::cout << "==============================\n";
    std::cout << "性能测试报告\n";
    std::cout << "数据块大小: " << data_size << " bytes\n";
    std::cout << "迭代次数: " << iterations << "\n";
    std::cout << "总处理数据: " << total_bytes / (1024 * 1024) << " MB\n";
    std::cout << "总耗时: " << total_seconds << " 秒\n";
    std::cout << "哈希速度: " << speed_mbps << " Mbps\n";
    std::cout << "平均耗时: " << duration / iterations << " 微秒/次\n";
}


// 主测试函数
int main() {
    // 基础测试（验证正确性）
    const char* test_str = "abc";
    uint8_t hash[32];
    sm3(reinterpret_cast<const uint8_t*>(test_str), strlen(test_str), hash);

    std::cout << "SM3(\"abc\") = ";
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
    }
    std::cout << std::dec << "\n\n";

    // 性能测试（不同数据规模）
    performance_test(1 * 1024, 10000);       // 1KB数据测试
    performance_test(10 * 1024, 1000);       // 10KB数据测试
    performance_test(100 * 1024, 100);       // 100KB数据测试
    performance_test(1 * 1024 * 1024, 10);   // 1MB数据测试

    return 0;

}
