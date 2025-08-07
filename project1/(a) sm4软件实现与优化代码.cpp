#include <iostream>
#include<vector>
#include<array>
#include<cstddef>
#include <cstdint>
#include <emmintrin.h>

// 防止编译器优化掉关键操作
volatile uint8_t prevent_optimization;

// trival SM4 based on Sbox
void xor4Bytes(uint8_t result[4], const uint8_t a[4], const uint8_t b[4], const uint8_t c[4], const uint8_t d[4]) { for (int i = 0; i < 4; ++i) result[i] = a[i] ^ b[i] ^ c[i] ^ d[i]; }
void xor2Bytes(uint8_t result[4], const uint8_t a[4], const uint8_t b[4]) { for (int i = 0; i < 4; ++i) result[i] = a[i] ^ b[i]; }
void xor5Bytes(uint8_t result[4], const uint8_t a[4], const uint8_t b[4], const uint8_t c[4], const uint8_t d[4], const uint8_t e[4]) {
    for (int i = 0; i < 4; ++i) result[i] = a[i] ^ b[i] ^ c[i] ^ d[i] ^ e[i];
}

uint8_t Plaintext[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
uint8_t Key[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10 };
uint8_t Sbox[256] = {
    0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05,
    0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62,
    0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6,
    0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8,
    0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35,
    0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87,
    0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e,
    0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1,
    0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3,
    0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f,
    0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51,
    0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8,
    0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0,
    0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84,
    0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48
};
uint32_t FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
uint32_t CK[32] = {
    0x00070e15, 0x1c232a31, 0x383f464d, 0x545b6269,
    0x70777e85, 0x8c939aa1, 0xa8afb6bd, 0xc4cbd2d9,
    0xe0e7eef5, 0xfc030a11, 0x181f262d, 0x343b4249,
    0x50575e65, 0x6c737a81, 0x888f969d, 0xa4abb2b9,
    0xc0c7ced5, 0xdce3eaf1, 0xf8ff060d, 0x141b2229,
    0x30373e45, 0x4c535a61, 0x686f767d, 0x848b9299,
    0xa0a7aeb5, 0xbcc3cad1, 0xd8dfe6ed, 0xf4fb0209,
    0x10171e25, 0x2c333a41, 0x484f565d, 0x646b7279
};

uint8_t* T_func(uint8_t* x) {
    static uint8_t result[4];

    // S盒代换
    uint8_t b[4];
    for (int i = 0; i < 4; ++i) {
        b[i] = Sbox[x[i]];
    }

    // 将4字节组合成32位字（大端序）
    uint32_t word = (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];

    // 线性变换L: 循环左移并异或
    uint32_t L = word
        ^ ((word << 2) | (word >> 30))   // 循环左移2位
        ^ ((word << 10) | (word >> 22))  // 循环左移10位
        ^ ((word << 18) | (word >> 14))  // 循环左移18位
        ^ ((word << 24) | (word >> 8));  // 循环左移24位

    // 将32位结果拆分为4字节
    result[0] = (L >> 24) & 0xFF;
    result[1] = (L >> 16) & 0xFF;
    result[2] = (L >> 8) & 0xFF;
    result[3] = L & 0xFF;

    return result;
}

uint8_t* SM4Round(uint8_t x1[4], uint8_t x2[4], uint8_t x3[4], uint8_t x4[4], uint8_t* rk) {
    uint8_t result[4];
    uint8_t temp[4];
    xor4Bytes(temp, x2, x3, x4, rk);
    xor2Bytes(result, x1, T_func(temp));
    return result;
}

uint32_t T_Kgen(uint32_t K) {
    static uint8_t A[4];
    static uint8_t B[4];
    // 将32位结果拆分为4字节
    A[0] = (K >> 24) & 0xFF;
    A[1] = (K >> 16) & 0xFF;
    A[2] = (K >> 8) & 0xFF;
    A[3] = K & 0xFF;
    // S盒代换
    for (int i = 0; i < 4; ++i) {
        B[i] = Sbox[A[i]];
    }
    // 将4字节组合成32位字（大端序）
    uint32_t word = (B[0] << 24) | (B[1] << 16) | (B[2] << 8) | B[3];
    // 线性变换L: 循环左移并异或
    uint32_t L = word
        ^ ((word << 13) | (word >> 19))   // 循环左移13位
        ^ ((word << 23) | (word >> 9));  // 循环左移23位
    return L;
}

void RoundKeyGen(uint32_t rk[32], uint8_t key[16]) {
    uint32_t K[36];
    uint32_t key_word[4];
    key_word[0] = key[0] | key[1] | key[2] | key[3];
    key_word[1] = key[4] | key[5] | key[6] | key[7];
    key_word[2] = key[8] | key[9] | key[10] | key[11];
    key_word[3] = key[12] | key[13] | key[14] | key[15];
    for (int i = 0; i < 4; ++i) {
        K[i] = key_word[i] ^ FK[i];
    }
    for (int i = 4; i < 36; ++i) {
        K[i] = K[i - 4] ^ T_Kgen(K[i - 1] ^ K[i - 2] ^ K[i - 3] ^ CK[i - 4]);
    }
    for (int i = 0; i < 32; ++i) {
        rk[i] = K[i + 4];
    }
}

void SM4Encrypt(uint8_t* input, uint8_t* output, uint32_t rk[32]) {
    uint8_t x[36][4];
    for (int i = 0; i < 16; ++i) { // initial vector
        x[0][i] = input[i];
    }
    for (int i = 0; i < 32; ++i) { // round func
        uint8_t* temp = SM4Round(x[i], x[i + 1], x[i + 2], x[i + 3], (uint8_t*)&rk[i]);
        x[i + 4][0] = temp[0];
        x[i + 4][1] = temp[1];
        x[i + 4][2] = temp[2];
        x[i + 4][3] = temp[3];
    }
    // reverse
    output[0] = x[35][0];
    output[1] = x[35][1];
    output[2] = x[35][2];
    output[3] = x[35][3];
    output[4] = x[34][0];
    output[5] = x[34][1];
    output[6] = x[34][2];
    output[7] = x[34][3];
    output[8] = x[33][0];
    output[9] = x[33][1];
    output[10] = x[33][2];
    output[11] = x[33][3];
    output[12] = x[32][0];
    output[13] = x[32][1];
    output[14] = x[32][2];
    output[15] = x[32][3];
    // End of the Encryption
}

//优化
#include <iostream>
#include <cstdint>

// 预计算T-table
uint32_t T_table[256];

// 初始化T-table
void init_T_table() {
    for (int i = 0; i < 256; ++i) {
        uint8_t b = Sbox[i];
        uint32_t word = b << 24; // 相当于b在最高字节位置

        // 线性变换L
        uint32_t L = word
            ^ ((word << 2) | (word >> 30))   // 循环左移2位
            ^ ((word << 10) | (word >> 22))  // 循环左移10位
            ^ ((word << 18) | (word >> 14))  // 循环左移18位
            ^ ((word << 24) | (word >> 8));  // 循环左移24位

        T_table[i] = L;
    }
}

// 优化后的T_func使用T-table
uint32_t T_func_optimized(uint32_t word) {
    uint32_t result = 0;
    result ^= T_table[(word >> 24) & 0xFF];
    result ^= (T_table[(word >> 16) & 0xFF] >> 8) | (T_table[(word >> 16) & 0xFF] << 24);
    result ^= (T_table[(word >> 8) & 0xFF] >> 16) | (T_table[(word >> 8) & 0xFF] << 16);
    result ^= (T_table[word & 0xFF] >> 24) | (T_table[word & 0xFF] << 8);
    return result;
}

// 优化后的轮函数
uint32_t SM4Round_optimized(uint32_t x1, uint32_t x2, uint32_t x3, uint32_t x4, uint32_t rk) {
    return x1 ^ T_func_optimized(x2 ^ x3 ^ x4 ^ rk);
}

// 优化后的加密函数
void SM4Encrypt_optimized(const uint8_t* input, uint8_t* output, const uint32_t rk[32]) {
    // 初始化T-table (实际应用中只需初始化一次)
    static bool table_initialized = false;
    if (!table_initialized) {
        init_T_table();
        table_initialized = true;
    }

    // 将输入转换为32位字 (大端序)
    uint32_t x[36];
    x[0] = (input[0] << 24) | (input[1] << 16) | (input[2] << 8) | input[3];
    x[1] = (input[4] << 24) | (input[5] << 16) | (input[6] << 8) | input[7];
    x[2] = (input[8] << 24) | (input[9] << 16) | (input[10] << 8) | input[11];
    x[3] = (input[12] << 24) | (input[13] << 16) | (input[14] << 8) | input[15];

    // 32轮加密 (部分展开)
    for (int i = 0; i < 32; i += 4) {
        x[i + 4] = SM4Round_optimized(x[i], x[i + 1], x[i + 2], x[i + 3], rk[i]);
        x[i + 5] = SM4Round_optimized(x[i + 1], x[i + 2], x[i + 3], x[i + 4], rk[i + 1]);
        x[i + 6] = SM4Round_optimized(x[i + 2], x[i + 3], x[i + 4], x[i + 5], rk[i + 2]);
        x[i + 7] = SM4Round_optimized(x[i + 3], x[i + 4], x[i + 5], x[i + 6], rk[i + 3]);
    }

    // 反序变换并输出
    uint32_t out0 = x[35], out1 = x[34], out2 = x[33], out3 = x[32];
    output[0] = (out0 >> 24) & 0xFF;
    output[1] = (out0 >> 16) & 0xFF;
    output[2] = (out0 >> 8) & 0xFF;
    output[3] = out0 & 0xFF;
    output[4] = (out1 >> 24) & 0xFF;
    output[5] = (out1 >> 16) & 0xFF;
    output[6] = (out1 >> 8) & 0xFF;
    output[7] = out1 & 0xFF;
    output[8] = (out2 >> 24) & 0xFF;
    output[9] = (out2 >> 16) & 0xFF;
    output[10] = (out2 >> 8) & 0xFF;
    output[11] = out2 & 0xFF;
    output[12] = (out3 >> 24) & 0xFF;
    output[13] = (out3 >> 16) & 0xFF;
    output[14] = (out3 >> 8) & 0xFF;
    output[15] = out3 & 0xFF;
}




// Benchmark Phase
#include <chrono>
#include <random>
#include <iomanip>

// 生成随机数据填充缓冲区
void generate_random_data(uint8_t* data, size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }
}

// 基准测试函数



void benchmark_SM4() {
    constexpr int WARMUP_ITERATIONS = 100;
    constexpr int TEST_ITERATIONS = 10000;
    constexpr int BLOCK_SIZE = 16; // SM4块大小

    // 准备测试数据
    uint32_t rk[32];
    RoundKeyGen(rk, Key);

    uint8_t plaintext[BLOCK_SIZE];
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];

    // 准备大缓冲区用于吞吐量测试
    constexpr size_t LARGE_BUFFER_SIZE = 1024 * 1024; // 1MB
    uint8_t* large_plain = new uint8_t[LARGE_BUFFER_SIZE];
    uint8_t* large_cipher = new uint8_t[LARGE_BUFFER_SIZE];
    uint8_t* large_decrypted = new uint8_t[LARGE_BUFFER_SIZE];

    generate_random_data(large_plain, LARGE_BUFFER_SIZE);

    // 预热
    for (int i = 0; i < WARMUP_ITERATIONS; ++i) {
        SM4Encrypt(plaintext, ciphertext, rk);
        prevent_optimization = ciphertext[0]; // 防止优化
    }

    // 测试单次加密延迟
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        SM4Encrypt(plaintext, ciphertext, rk);
        prevent_optimization ^= ciphertext[0]; // 防止优化
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_encrypt_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 测试单次解密延迟
    uint32_t decrypt_rk[32];
    for (int i = 0; i < 32; ++i) {
        decrypt_rk[i] = rk[31 - i];
    }

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        SM4Encrypt(ciphertext, decrypted, decrypt_rk);
        prevent_optimization ^= decrypted[0]; // 防止优化
    }
    end = std::chrono::high_resolution_clock::now();

    duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_decrypt_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 测试吞吐量 (1MB数据加密)
    const int blocks = LARGE_BUFFER_SIZE / BLOCK_SIZE;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < blocks; ++i) {
        SM4Encrypt(large_plain + i * BLOCK_SIZE,
            large_cipher + i * BLOCK_SIZE, rk);
    }
    end = std::chrono::high_resolution_clock::now();

    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double encrypt_throughput = (LARGE_BUFFER_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 测试吞吐量 (1MB数据解密)
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < blocks; ++i) {
        SM4Encrypt(large_cipher + i * BLOCK_SIZE,
            large_decrypted + i * BLOCK_SIZE, decrypt_rk);
    }
    end = std::chrono::high_resolution_clock::now();

    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double decrypt_throughput = (LARGE_BUFFER_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 清理内存
    delete[] large_plain;
    delete[] large_cipher;
    delete[] large_decrypted;

    std::cout << "===============================\n";

    std::cout << "优化前性能测试:\n\n";

    std::cout << "单次操作延迟:\n";
    std::cout << "  加密: " << std::fixed << std::setprecision(2) << avg_encrypt_ns << " ns\n";
    std::cout << "  解密: " << std::fixed << std::setprecision(2) << avg_decrypt_ns << " ns\n\n";

    std::cout << "吞吐量 (1MB数据):\n";
    std::cout << "  加密: " << std::fixed << std::setprecision(2) << encrypt_throughput << " MB/s\n";
    std::cout << "  解密: " << std::fixed << std::setprecision(2) << decrypt_throughput << " MB/s\n";

}

// End of Benchmark





void benchmark_SM4_opt() {
    constexpr int WARMUP_ITERATIONS = 100;
    constexpr int TEST_ITERATIONS = 10000;
    constexpr int BLOCK_SIZE = 16; // SM4块大小

    // 准备测试数据
    uint32_t rk[32];
    RoundKeyGen(rk, Key);

    uint8_t plaintext[BLOCK_SIZE];
    uint8_t ciphertext[BLOCK_SIZE];
    uint8_t decrypted[BLOCK_SIZE];

    // 准备大缓冲区用于吞吐量测试
    constexpr size_t LARGE_BUFFER_SIZE = 1024 * 1024; // 1MB
    uint8_t* large_plain = new uint8_t[LARGE_BUFFER_SIZE];
    uint8_t* large_cipher = new uint8_t[LARGE_BUFFER_SIZE];
    uint8_t* large_decrypted = new uint8_t[LARGE_BUFFER_SIZE];

    generate_random_data(large_plain, LARGE_BUFFER_SIZE);

    // 预热
    for (int i = 0; i < WARMUP_ITERATIONS; ++i) {
        SM4Encrypt_optimized(plaintext, ciphertext, rk);
        prevent_optimization = ciphertext[0]; // 防止优化
    }

    // 测试单次加密延迟
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        SM4Encrypt_optimized(plaintext, ciphertext, rk);
        prevent_optimization ^= ciphertext[0]; // 防止优化
    }
    auto end = std::chrono::high_resolution_clock::now();

    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_encrypt_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 测试单次解密延迟
    uint32_t decrypt_rk[32];
    for (int i = 0; i < 32; ++i) {
        decrypt_rk[i] = rk[31 - i];
    }

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        SM4Encrypt_optimized(ciphertext, decrypted, decrypt_rk);
        prevent_optimization ^= decrypted[0]; // 防止优化
    }
    end = std::chrono::high_resolution_clock::now();

    duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_decrypt_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 测试吞吐量 (1MB数据加密)
    const int blocks = LARGE_BUFFER_SIZE / BLOCK_SIZE;

    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < blocks; ++i) {
        SM4Encrypt_optimized(large_plain + i * BLOCK_SIZE,
            large_cipher + i * BLOCK_SIZE, rk);
    }
    end = std::chrono::high_resolution_clock::now();

    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double encrypt_throughput = (LARGE_BUFFER_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 测试吞吐量 (1MB数据解密)
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < blocks; ++i) {
        SM4Encrypt_optimized(large_cipher + i * BLOCK_SIZE,
            large_decrypted + i * BLOCK_SIZE, decrypt_rk);
    }
    end = std::chrono::high_resolution_clock::now();

    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double decrypt_throughput = (LARGE_BUFFER_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 清理内存
    delete[] large_plain;
    delete[] large_cipher;
    delete[] large_decrypted;

    std::cout << "===============================\n";

    std::cout << "优化后性能测试:\n\n";

    std::cout << "单次操作延迟:\n";
    std::cout << "  加密: " << std::fixed << std::setprecision(2) << avg_encrypt_ns << " ns\n";
    std::cout << "  解密: " << std::fixed << std::setprecision(2) << avg_decrypt_ns << " ns\n\n";

    std::cout << "吞吐量 (1MB数据):\n";
    std::cout << "  加密: " << std::fixed << std::setprecision(2) << encrypt_throughput << " MB/s\n";
    std::cout << "  解密: " << std::fixed << std::setprecision(2) << decrypt_throughput << " MB/s\n";

}



int main()
{
    uint32_t rk[32];
    RoundKeyGen(rk, Key);
    uint8_t output[16];
    SM4Encrypt(Plaintext, output, rk);
    std::cout << "加密结果: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << (int)output[i] << " ";
    }
    std::cout << std::endl;

    /// 逆序解密
    uint32_t rk2[32];
    for (int i = 0; i < 32; ++i) {
        rk2[i] = rk[31 - i];
    }
    uint8_t PLT[16];
    SM4Encrypt(output, PLT, rk2);
    std::cout << "解密结果: ";
    for (int i = 0; i < 16; ++i) {
        std::cout << std::hex << (int)PLT[i] << " ";
    }
    std::cout << std::endl;

    // 运行性能测试
    benchmark_SM4();

    //优化后的性能测试
    benchmark_SM4_opt();
    return 0;
}
