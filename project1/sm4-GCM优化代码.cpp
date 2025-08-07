#include <iostream>
#include <vector>
#include <array>
#include <cstddef>
#include <cstdint>
#include <emmintrin.h>
#include <chrono>
#include <random>
#include <iomanip>

// 防止编译器优化
volatile uint8_t prevent_optimization;

// ==================== 原始SM4实现 ====================
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
// 辅助函数
void xor_block(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

uint32_t T_Kgen(uint32_t K) {
    uint8_t A[4];
    uint8_t B[4];
    A[0] = (K >> 24) & 0xFF;
    A[1] = (K >> 16) & 0xFF;
    A[2] = (K >> 8) & 0xFF;
    A[3] = K & 0xFF;

    for (int i = 0; i < 4; ++i) {
        B[i] = Sbox[A[i]];
    }

    uint32_t word = (B[0] << 24) | (B[1] << 16) | (B[2] << 8) | B[3];
    return word ^ ((word << 13) | (word >> 19)) ^ ((word << 23) | (word >> 9));
}

void RoundKeyGen(uint32_t rk[32], const uint8_t key[16]) {
    uint32_t K[36];
    uint32_t key_word[4];

    for (int i = 0; i < 4; ++i) {
        key_word[i] = (key[i * 4] << 24) | (key[i * 4 + 1] << 16) | (key[i * 4 + 2] << 8) | key[i * 4 + 3];
        K[i] = key_word[i] ^ FK[i];
    }

    for (int i = 4; i < 36; ++i) {
        K[i] = K[i - 4] ^ T_Kgen(K[i - 1] ^ K[i - 2] ^ K[i - 3] ^ CK[i - 4]);
    }

    for (int i = 0; i < 32; ++i) {
        rk[i] = K[i + 4];
    }
}

void SM4_Encrypt_Block(const uint8_t* input, uint8_t* output, const uint32_t rk[32]) {
    uint32_t x[36];

    // 初始化
    for (int i = 0; i < 4; ++i) {
        x[i] = (input[i * 4] << 24) | (input[i * 4 + 1] << 16) | (input[i * 4 + 2] << 8) | input[i * 4 + 3];
    }

    // 32轮加密
    for (int i = 0; i < 32; ++i) {
        uint32_t temp = x[i + 1] ^ x[i + 2] ^ x[i + 3] ^ rk[i];

        // S盒替换
        uint32_t sbox_out = (Sbox[(temp >> 24) & 0xFF] << 24) |
            (Sbox[(temp >> 16) & 0xFF] << 16) |
            (Sbox[(temp >> 8) & 0xFF] << 8) |
            Sbox[temp & 0xFF];

        // 线性变换L
        uint32_t L = sbox_out ^ ((sbox_out << 2) | (sbox_out >> 30)) ^
            ((sbox_out << 10) | (sbox_out >> 22)) ^
            ((sbox_out << 18) | (sbox_out >> 14)) ^
            ((sbox_out << 24) | (sbox_out >> 8));

        x[i + 4] = x[i] ^ L;
    }

    // 反序输出
    for (int i = 0; i < 4; ++i) {
        output[i] = (x[35 - i] >> 24) & 0xFF;
        output[i + 4] = (x[35 - i] >> 16) & 0xFF;
        output[i + 8] = (x[35 - i] >> 8) & 0xFF;
        output[i + 12] = x[35 - i] & 0xFF;
    }
}

// ==================== SM4-GCM实现 ====================

// GCM上下文结构
typedef struct {
    uint8_t H[16];          // E_k(0^128)
    uint8_t J0[16];         // 初始计数器
    uint8_t key[16];        // 加密密钥
    uint32_t rk[32];        // 轮密钥
    uint64_t ghash_table[16][256]; // GF(2^128)乘法表
} sm4_gcm_ctx;

// 简化的GF(2^8)乘法
uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi_bit = (a & 0x80);
        a <<= 1;
        if (hi_bit) a ^= 0x1b; // x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return p;
}

// 初始化GHASH乘法表
void init_ghash_table(const uint8_t H[16], uint64_t table[16][256]) {
    uint8_t tmp[16] = { 0 };
    uint8_t product[16] = { 0 };

    // 预计算所有可能的乘法结果
    for (int i = 0; i < 16; ++i) {
        for (int j = 0; j < 256; ++j) {
            memset(tmp, 0, 16);
            tmp[i] = j;

            // 简化的GF(2^128)乘法
            memset(product, 0, 16);
            for (int k = 0; k < 16; ++k) {
                if (tmp[k]) {
                    for (int l = 0; l < 16; ++l) {
                        product[k + l >= 16 ? k + l - 16 : k + l] ^= gmul(tmp[k], H[l]);
                    }
                }
            }

            // 存储到表中
            memcpy(&table[i][j], product, 16);
        }
    }
}

// 计数器递增
void increment_ctr(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; --i) {
        if (++ctr[i] != 0) break;
    }
}

// 优化前的GHASH实现（基础版本）
void ghash_basic(const uint8_t H[16],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    uint8_t* output) {
    uint8_t X[16] = { 0 };
    size_t i;

    // 处理AAD
    for (i = 0; i < aad_len; i += 16) {
        size_t block_len = (aad_len - i) < 16 ? (aad_len - i) : 16;
        uint8_t block[16] = { 0 };
        memcpy(block, aad + i, block_len);
        xor_block(X, block, X, 16);

        // GF(2^128)乘法
        uint8_t Z[16] = { 0 };
        for (int k = 0; k < 16; ++k) {
            if (X[k]) {
                for (int l = 0; l < 16; ++l) {
                    Z[k + l >= 16 ? k + l - 16 : k + l] ^= gmul(X[k], H[l]);
                }
            }
        }
        memcpy(X, Z, 16);
    }

    // 处理密文
    for (i = 0; i < ct_len; i += 16) {
        size_t block_len = (ct_len - i) < 16 ? (ct_len - i) : 16;
        uint8_t block[16] = { 0 };
        memcpy(block, ciphertext + i, block_len);
        xor_block(X, block, X, 16);

        // GF(2^128)乘法
        uint8_t Z[16] = { 0 };
        for (int k = 0; k < 16; ++k) {
            if (X[k]) {
                for (int l = 0; l < 16; ++l) {
                    Z[k + l >= 16 ? k + l - 16 : k + l] ^= gmul(X[k], H[l]);
                }
            }
        }
        memcpy(X, Z, 16);
    }

    // 处理长度块
    uint8_t len_block[16] = { 0 };
    *((uint64_t*)len_block + 0) = aad_len * 8;
    *((uint64_t*)len_block + 1) = ct_len * 8;
    xor_block(X, len_block, X, 16);

    // GF(2^128)乘法
    uint8_t Z[16] = { 0 };
    for (int k = 0; k < 16; ++k) {
        if (X[k]) {
            for (int l = 0; l < 16; ++l) {
                Z[k + l >= 16 ? k + l - 16 : k + l] ^= gmul(X[k], H[l]);
            }
        }
    }
    memcpy(output, Z, 16);
}

// 优化后的GHASH实现（查表法）
void ghash_optimized(const uint64_t table[16][256],
    const uint8_t* aad, size_t aad_len,
    const uint8_t* ciphertext, size_t ct_len,
    uint8_t* output) {
    uint64_t X[2] = { 0 };
    size_t i;

    // 处理AAD
    for (i = 0; i < aad_len; i += 16) {
        size_t block_len = (aad_len - i) < 16 ? (aad_len - i) : 16;
        uint8_t block[16] = { 0 };
        memcpy(block, aad + i, block_len);

        for (int j = 0; j < 16; ++j) {
            const uint64_t* row = &table[j][block[j]];
            X[0] ^= row[0];
            X[1] ^= row[1];
        }
    }

    // 处理密文
    for (i = 0; i < ct_len; i += 16) {
        size_t block_len = (ct_len - i) < 16 ? (ct_len - i) : 16;
        uint8_t block[16] = { 0 };
        memcpy(block, ciphertext + i, block_len);

        for (int j = 0; j < 16; ++j) {
            const uint64_t* row = &table[j][block[j]];
            X[0] ^= row[0];
            X[1] ^= row[1];
        }
    }

    // 处理长度块
    uint8_t len_block[16] = { 0 };
    *((uint64_t*)len_block + 0) = aad_len * 8;
    *((uint64_t*)len_block + 1) = ct_len * 8;

    for (int j = 0; j < 16; ++j) {
        const uint64_t* row = &table[j][len_block[j]];
        X[0] ^= row[0];
        X[1] ^= row[1];
    }

    memcpy(output, X, 16);
}

// 初始化SM4-GCM上下文
void sm4_gcm_init(sm4_gcm_ctx* ctx, const uint8_t* key, const uint8_t* iv, size_t iv_len, bool use_optimization) {
    // 1. 保存密钥并生成轮密钥
    memcpy(ctx->key, key, 16);
    RoundKeyGen(ctx->rk, key);

    // 2. 计算H = SM4_Encrypt(key, 0^128)
    memset(ctx->H, 0, 16);
    SM4_Encrypt_Block(ctx->H, ctx->H, ctx->rk);

    // 3. 初始化GHASH乘法表（仅在优化版本中使用）
    if (use_optimization) {
        init_ghash_table(ctx->H, ctx->ghash_table);
    }

    // 4. 生成J0计数器
    if (iv_len == 12) {
        memcpy(ctx->J0, iv, 12);
        memset(ctx->J0 + 12, 0, 3);
        ctx->J0[15] = 1;
    }
    else {
        // 对于非12字节IV，需要GHASH处理
        memset(ctx->J0, 0, 16);
        size_t iv_blocks = (iv_len + 15) / 16;

        for (size_t i = 0; i < iv_blocks; ++i) {
            size_t block_len = (i == iv_blocks - 1) ? iv_len % 16 : 16;
            if (block_len == 0) block_len = 16;

            uint8_t block[16] = { 0 };
            memcpy(block, iv + i * 16, block_len);

            if (use_optimization) {
                for (int j = 0; j < 16; ++j) {
                    uint64_t* row = &ctx->ghash_table[j][block[j]];
                    for (int k = 0; k < 2; ++k) {
                        *((uint64_t*)ctx->J0 + k) ^= row[k];
                    }
                }
            }
            else {
                xor_block(ctx->J0, block, ctx->J0, 16);

                uint8_t Z[16] = { 0 };
                for (int k = 0; k < 16; ++k) {
                    if (ctx->J0[k]) {
                        for (int l = 0; l < 16; ++l) {
                            Z[k + l >= 16 ? k + l - 16 : k + l] ^= gmul(ctx->J0[k], ctx->H[l]);
                        }
                    }
                }
                memcpy(ctx->J0, Z, 16);
            }
        }

        // 处理长度块
        uint8_t len_block[16] = { 0 };
        *((uint64_t*)len_block + 1) = iv_len * 8;

        if (use_optimization) {
            for (int j = 0; j < 16; ++j) {
                uint64_t* row = &ctx->ghash_table[j][len_block[j]];
                for (int k = 0; k < 2; ++k) {
                    *((uint64_t*)ctx->J0 + k) ^= row[k];
                }
            }
        }
        else {
            xor_block(ctx->J0, len_block, ctx->J0, 16);

            uint8_t Z[16] = { 0 };
            for (int k = 0; k < 16; ++k) {
                if (ctx->J0[k]) {
                    for (int l = 0; l < 16; ++l) {
                        Z[k + l >= 16 ? k + l - 16 : k + l] ^= gmul(ctx->J0[k], ctx->H[l]);
                    }
                }
            }
            memcpy(ctx->J0, Z, 16);
        }
    }
}

// SM4-GCM加密（基础版本）
void sm4_gcm_encrypt_basic(sm4_gcm_ctx* ctx,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext,
    const uint8_t* aad, size_t aad_len,
    uint8_t* tag) {
    uint8_t ctr[16];
    uint8_t keystream[16];
    size_t i;

    // 1. 初始化计数器
    memcpy(ctr, ctx->J0, 16);
    increment_ctr(ctr);

    // 2. CTR模式加密
    for (i = 0; i < pt_len; i += 16) {
        // 生成密钥流
        SM4_Encrypt_Block(ctr, keystream, ctx->rk);
        increment_ctr(ctr);

        // 加密当前块
        size_t block_len = (pt_len - i) < 16 ? (pt_len - i) : 16;
        xor_block(plaintext + i, keystream, ciphertext + i, block_len);
    }

    // 3. 计算认证标签
    uint8_t auth_tag[16];
    ghash_basic(ctx->H, aad, aad_len, ciphertext, pt_len, auth_tag);

    // 4. 加密认证标签
    SM4_Encrypt_Block(ctx->J0, tag, ctx->rk);
    xor_block(tag, auth_tag, tag, 16);
}

// SM4-GCM加密（优化版本）
void sm4_gcm_encrypt_optimized(sm4_gcm_ctx* ctx,
    const uint8_t* plaintext, size_t pt_len,
    uint8_t* ciphertext,
    const uint8_t* aad, size_t aad_len,
    uint8_t* tag) {
    uint8_t ctr[16];
    uint8_t keystream[16];
    size_t i;

    // 1. 初始化计数器
    memcpy(ctr, ctx->J0, 16);
    increment_ctr(ctr);

    // 2. CTR模式加密
    for (i = 0; i < pt_len; i += 16) {
        // 生成密钥流
        SM4_Encrypt_Block(ctr, keystream, ctx->rk);
        increment_ctr(ctr);

        // 加密当前块
        size_t block_len = (pt_len - i) < 16 ? (pt_len - i) : 16;
        xor_block(plaintext + i, keystream, ciphertext + i, block_len);
    }

    // 3. 计算认证标签
    uint8_t auth_tag[16];
    ghash_optimized(ctx->ghash_table, aad, aad_len, ciphertext, pt_len, auth_tag);

    // 4. 加密认证标签
    SM4_Encrypt_Block(ctx->J0, tag, ctx->rk);
    xor_block(tag, auth_tag, tag, 16);
}

// SM4-GCM解密（基础版本）
void sm4_gcm_decrypt_basic(sm4_gcm_ctx* ctx,
    const uint8_t* ciphertext, size_t ct_len,
    uint8_t* plaintext,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag) {
    uint8_t ctr[16];
    uint8_t keystream[16];
    size_t i;

    // 1. 初始化计数器
    memcpy(ctr, ctx->J0, 16);
    increment_ctr(ctr);

    // 2. CTR模式解密
    for (i = 0; i < ct_len; i += 16) {
        // 生成密钥流
        SM4_Encrypt_Block(ctr, keystream, ctx->rk);
        increment_ctr(ctr);

        // 解密当前块
        size_t block_len = (ct_len - i) < 16 ? (ct_len - i) : 16;
        xor_block(ciphertext + i, keystream, plaintext + i, block_len);
    }

    // 3. 验证标签
    uint8_t computed_tag[16];
    ghash_basic(ctx->H, aad, aad_len, ciphertext, ct_len, computed_tag);
    SM4_Encrypt_Block(ctx->J0, computed_tag, ctx->rk);

    // 比较标签
    bool auth_ok = true;
    for (int j = 0; j < 16; ++j) {
        if (computed_tag[j] != tag[j]) {
            auth_ok = false;
            break;
        }
    }

    if (!auth_ok) {
        memset(plaintext, 0, ct_len); // 认证失败时清空明文
    }
}

// SM4-GCM解密（优化版本）
void sm4_gcm_decrypt_optimized(sm4_gcm_ctx* ctx,
    const uint8_t* ciphertext, size_t ct_len,
    uint8_t* plaintext,
    const uint8_t* aad, size_t aad_len,
    const uint8_t* tag) {
    uint8_t ctr[16];
    uint8_t keystream[16];
    size_t i;

    // 1. 初始化计数器
    memcpy(ctr, ctx->J0, 16);
    increment_ctr(ctr);

    // 2. CTR模式解密
    for (i = 0; i < ct_len; i += 16) {
        // 生成密钥流
        SM4_Encrypt_Block(ctr, keystream, ctx->rk);
        increment_ctr(ctr);

        // 解密当前块
        size_t block_len = (ct_len - i) < 16 ? (ct_len - i) : 16;
        xor_block(ciphertext + i, keystream, plaintext + i, block_len);
    }

    // 3. 验证标签
    uint8_t computed_tag[16];
    ghash_optimized(ctx->ghash_table, aad, aad_len, ciphertext, ct_len, computed_tag);
    SM4_Encrypt_Block(ctx->J0, computed_tag, ctx->rk);

    // 比较标签
    bool auth_ok = true;
    for (int j = 0; j < 16; ++j) {
        if (computed_tag[j] != tag[j]) {
            auth_ok = false;
            break;
        }
    }

    if (!auth_ok) {
        memset(plaintext, 0, ct_len); // 认证失败时清空明文
    }
}

// ==================== 测试代码 ====================

// 生成随机数据
void generate_random_data(uint8_t* data, size_t size) {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, 255);

    for (size_t i = 0; i < size; ++i) {
        data[i] = static_cast<uint8_t>(dis(gen));
    }
}

// 性能测试函数
void benchmark_sm4_gcm() {
    const int WARMUP_ITERATIONS = 100;
    const int TEST_ITERATIONS = 1000;
    const size_t SMALL_DATA_SIZE = 64;    // 64字节小数据测试
    const size_t LARGE_DATA_SIZE = 1024 * 1024; // 1MB大数据测试

    // 准备测试数据
    uint8_t key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    uint8_t iv[12] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                     0x99, 0xaa, 0xbb, 0xcc };
    uint8_t aad[32] = { 0 }; // 32字节附加认证数据

    uint8_t* small_plain = new uint8_t[SMALL_DATA_SIZE];
    uint8_t* small_cipher_basic = new uint8_t[SMALL_DATA_SIZE];
    uint8_t* small_cipher_opt = new uint8_t[SMALL_DATA_SIZE];
    uint8_t* small_decrypted_basic = new uint8_t[SMALL_DATA_SIZE];
    uint8_t* small_decrypted_opt = new uint8_t[SMALL_DATA_SIZE];
    uint8_t tag_basic[16], tag_opt[16];

    uint8_t* large_plain = new uint8_t[LARGE_DATA_SIZE];
    uint8_t* large_cipher_basic = new uint8_t[LARGE_DATA_SIZE];
    uint8_t* large_cipher_opt = new uint8_t[LARGE_DATA_SIZE];
    uint8_t* large_decrypted_basic = new uint8_t[LARGE_DATA_SIZE];
    uint8_t* large_decrypted_opt = new uint8_t[LARGE_DATA_SIZE];

    generate_random_data(small_plain, SMALL_DATA_SIZE);
    generate_random_data(large_plain, LARGE_DATA_SIZE);
    generate_random_data(aad, 32);

    sm4_gcm_ctx ctx_basic, ctx_opt;

    // 初始化上下文
    sm4_gcm_init(&ctx_basic, key, iv, 12, false); // 基础版本
    sm4_gcm_init(&ctx_opt, key, iv, 12, true);    // 优化版本

    std::cout << "================ SM4-GCM 性能测试 ================\n";

    // ========== 小数据测试 ==========
    std::cout << "\n小数据测试 (64字节):\n";

    // 基础版本加密
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        sm4_gcm_encrypt_basic(&ctx_basic, small_plain, SMALL_DATA_SIZE,
            small_cipher_basic, aad, 32, tag_basic);
        prevent_optimization ^= small_cipher_basic[0];
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_encrypt_basic_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 优化版本加密
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        sm4_gcm_encrypt_optimized(&ctx_opt, small_plain, SMALL_DATA_SIZE,
            small_cipher_opt, aad, 32, tag_opt);
        prevent_optimization ^= small_cipher_opt[0];
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_encrypt_opt_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 基础版本解密
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        sm4_gcm_decrypt_basic(&ctx_basic, small_cipher_basic, SMALL_DATA_SIZE,
            small_decrypted_basic, aad, 32, tag_basic);
        prevent_optimization ^= small_decrypted_basic[0];
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_decrypt_basic_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 优化版本解密
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < TEST_ITERATIONS; ++i) {
        sm4_gcm_decrypt_optimized(&ctx_opt, small_cipher_opt, SMALL_DATA_SIZE,
            small_decrypted_opt, aad, 32, tag_opt);
        prevent_optimization ^= small_decrypted_opt[0];
    }
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::nanoseconds>(end - start).count();
    double avg_decrypt_opt_ns = static_cast<double>(duration) / TEST_ITERATIONS;

    // 输出小数据测试结果
    std::cout << "加密延迟:\n";
    std::cout << "  基础版本: " << std::fixed << std::setprecision(2) << avg_encrypt_basic_ns << " ns\n";
    std::cout << "  优化版本: " << std::fixed << std::setprecision(2) << avg_encrypt_opt_ns << " ns (";
    std::cout << std::setprecision(1) << (avg_encrypt_basic_ns / avg_encrypt_opt_ns) << "x faster)\n";

    std::cout << "解密延迟:\n";
    std::cout << "  基础版本: " << std::fixed << std::setprecision(2) << avg_decrypt_basic_ns << " ns\n";
    std::cout << "  优化版本: " << std::fixed << std::setprecision(2) << avg_decrypt_opt_ns << " ns (";
    std::cout << std::setprecision(1) << (avg_decrypt_basic_ns / avg_decrypt_opt_ns) << "x faster)\n";

    // ========== 大数据测试 ==========
    std::cout << "\n大数据测试 (1MB):\n";

    // 基础版本加密
    start = std::chrono::high_resolution_clock::now();
    sm4_gcm_encrypt_basic(&ctx_basic, large_plain, LARGE_DATA_SIZE,
        large_cipher_basic, aad, 32, tag_basic);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double encrypt_basic_throughput = (LARGE_DATA_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 优化版本加密
    start = std::chrono::high_resolution_clock::now();
    sm4_gcm_encrypt_optimized(&ctx_opt, large_plain, LARGE_DATA_SIZE,
        large_cipher_opt, aad, 32, tag_opt);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double encrypt_opt_throughput = (LARGE_DATA_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 基础版本解密
    start = std::chrono::high_resolution_clock::now();
    sm4_gcm_decrypt_basic(&ctx_basic, large_cipher_basic, LARGE_DATA_SIZE,
        large_decrypted_basic, aad, 32, tag_basic);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double decrypt_basic_throughput = (LARGE_DATA_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 优化版本解密
    start = std::chrono::high_resolution_clock::now();
    sm4_gcm_decrypt_optimized(&ctx_opt, large_cipher_opt, LARGE_DATA_SIZE,
        large_decrypted_opt, aad, 32, tag_opt);
    end = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    double decrypt_opt_throughput = (LARGE_DATA_SIZE / (1024.0 * 1024.0)) / (duration / 1000000.0);

    // 输出大数据测试结果
    std::cout << "加密吞吐量:\n";
    std::cout << "  基础版本: " << std::fixed << std::setprecision(2) << encrypt_basic_throughput << " MB/s\n";
    std::cout << "  优化版本: " << std::fixed << std::setprecision(2) << encrypt_opt_throughput << " MB/s (";
    std::cout << std::setprecision(1) << (encrypt_opt_throughput / encrypt_basic_throughput) << "x faster)\n";

    std::cout << "解密吞吐量:\n";
    std::cout << "  基础版本: " << std::fixed << std::setprecision(2) << decrypt_basic_throughput << " MB/s\n";
    std::cout << "  优化版本: " << std::fixed << std::setprecision(2) << decrypt_opt_throughput << " MB/s (";
    std::cout << std::setprecision(1) << (decrypt_opt_throughput / decrypt_basic_throughput) << "x faster)\n";

    // 验证解密正确性
    bool correct_basic = true;
    bool correct_opt = true;
    for (size_t i = 0; i < SMALL_DATA_SIZE; ++i) {
        if (small_plain[i] != small_decrypted_basic[i]) correct_basic = false;
        if (small_plain[i] != small_decrypted_opt[i]) correct_opt = false;
    }
    for (size_t i = 0; i < LARGE_DATA_SIZE; ++i) {
        if (large_plain[i] != large_decrypted_basic[i]) correct_basic = false;
        if (large_plain[i] != large_decrypted_opt[i]) correct_opt = false;
    }

    // 清理内存
    delete[] small_plain;
    delete[] small_cipher_basic;
    delete[] small_cipher_opt;
    delete[] small_decrypted_basic;
    delete[] small_decrypted_opt;
    delete[] large_plain;
    delete[] large_cipher_basic;
    delete[] large_cipher_opt;
    delete[] large_decrypted_basic;
    delete[] large_decrypted_opt;
}

// 主函数
int main() {
    // 基本功能测试
    uint8_t key[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    uint8_t iv[12] = { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                     0x99, 0xaa, 0xbb, 0xcc };
    uint8_t aad[32] = { 0 }; // 32字节附加认证数据
    uint8_t plaintext[64] = { 0 }; // 64字节测试明文
    uint8_t ciphertext_basic[64] = { 0 };
    uint8_t ciphertext_opt[64] = { 0 };
    uint8_t decrypted_basic[64] = { 0 };
    uint8_t decrypted_opt[64] = { 0 };
    uint8_t tag_basic[16] = { 0 };
    uint8_t tag_opt[16] = { 0 };

    // 填充测试数据
    for (int i = 0; i < 64; i++) {
        plaintext[i] = i;
    }
    for (int i = 0; i < 32; i++) {
        aad[i] = i;
    }

    sm4_gcm_ctx ctx_basic, ctx_opt;

    std::cout << "================ SM4-GCM 功能测试 ================\n";

    // 初始化上下文
    sm4_gcm_init(&ctx_basic, key, iv, 12, false); // 基础版本
    sm4_gcm_init(&ctx_opt, key, iv, 12, true);    // 优化版本

    // 基础版本加密解密
    sm4_gcm_encrypt_basic(&ctx_basic, plaintext, 64, ciphertext_basic, aad, 32, tag_basic);
    sm4_gcm_decrypt_basic(&ctx_basic, ciphertext_basic, 64, decrypted_basic, aad, 32, tag_basic);

    // 优化版本加密解密
    sm4_gcm_encrypt_optimized(&ctx_opt, plaintext, 64, ciphertext_opt, aad, 32, tag_opt);
    sm4_gcm_decrypt_optimized(&ctx_opt, ciphertext_opt, 64, decrypted_opt, aad, 32, tag_opt);

    // 验证结果
    bool basic_ok = true;
    bool opt_ok = true;
    for (int i = 0; i < 64; i++) {
        if (plaintext[i] != decrypted_basic[i]) basic_ok = false;
        if (plaintext[i] != decrypted_opt[i]) opt_ok = false;
    }

    // 运行性能测试
    benchmark_sm4_gcm();

    return 0;
}