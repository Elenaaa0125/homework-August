#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <random>
#include <iomanip>

#define ROTL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

// SM3À„∑® µœ÷
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

// Function to perform length extension attack
void length_extension_attack(const uint8_t* original_message, size_t original_len,
    const uint8_t* original_hash, const uint8_t* extension,
    size_t extension_len, uint8_t* new_hash) {
    // 1. Recover the internal state from the original hash
    uint32_t H[8];
    for (int i = 0; i < 8; i++) {
        H[i] = (original_hash[i * 4] << 24) | (original_hash[i * 4 + 1] << 16) |
            (original_hash[i * 4 + 2] << 8) | original_hash[i * 4 + 3];
    }

    // 2. Calculate the padded length of the original message
    size_t original_padded_len = ((original_len + 8 + 63) / 64) * 64;

    // 3. Create a new message that includes:
    //    - The original padding (without knowing the original message)
    //    - Our extension data
    //    - Proper padding for the new length

    // The new message length will be: original_padded_len + extension_len
    size_t new_len = original_padded_len + extension_len;
    size_t new_padded_len = ((new_len + 8 + 63) / 64) * 64;

    std::vector<uint8_t> new_message(new_padded_len, 0);

    // Place the extension data at the position where the original padding ended
    memcpy(new_message.data() + original_padded_len, extension, extension_len);

    // Add padding for the new message (including the original length)
    new_message[new_len] = 0x80;
    uint64_t bit_len = new_len * 8;
    for (int i = 0; i < 8; i++) {
        new_message[new_padded_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    }

    // 4. Compute the hash of the new message using the recovered state
    // Process only the new blocks (after original_padded_len)
    size_t extension_block_count = (extension_len + (new_padded_len - new_len) + 63) / 64;

    for (size_t i = 0; i < extension_block_count; i++) {
        uint32_t W[68];
        message_schedule(new_message.data() + original_padded_len + i * 64, W);

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

    // 5. Output the final hash
    for (int i = 0; i < 8; i++) {
        new_hash[i * 4] = (H[i] >> 24) & 0xff;
        new_hash[i * 4 + 1] = (H[i] >> 16) & 0xff;
        new_hash[i * 4 + 2] = (H[i] >> 8) & 0xff;
        new_hash[i * 4 + 3] = H[i] & 0xff;
    }
}

// Helper function to print hash
void print_hash(const uint8_t* hash) {
    for (int i = 0; i < 32; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    std::cout << std::dec << std::endl;
}

int main() {
    // Original message and its hash
    const char* original_msg = "This is a secret message";
    uint8_t original_hash[32];
    sm3(reinterpret_cast<const uint8_t*>(original_msg), strlen(original_msg), original_hash);

    std::cout << "Original message: " << original_msg << std::endl;
    std::cout << "Original hash: ";
    print_hash(original_hash);

    // Extension we want to add
    const char* extension = "malicious extension";

    // Perform the attack
    uint8_t new_hash[32];
    length_extension_attack(
        reinterpret_cast<const uint8_t*>(original_msg), strlen(original_msg),
        original_hash,
        reinterpret_cast<const uint8_t*>(extension), strlen(extension),
        new_hash
    );

    std::cout << "\nNew hash from attack: ";
    print_hash(new_hash);

    // Verification: Compute hash of (original_msg || padding || extension)
    // Should match the attack result

    // 1. Calculate padding for original message
    size_t original_len = strlen(original_msg);
    size_t original_padded_len = ((original_len + 8 + 63) / 64) * 64;
    std::vector<uint8_t> padded_original(original_padded_len, 0);
    memcpy(padded_original.data(), original_msg, original_len);
    padded_original[original_len] = 0x80;
    uint64_t bit_len = original_len * 8;
    for (int i = 0; i < 8; i++) {
        padded_original[original_padded_len - 8 + i] = (bit_len >> (56 - i * 8)) & 0xff;
    }

    // 2. Append extension
    std::vector<uint8_t> full_message(padded_original);
    full_message.insert(full_message.end(), extension, extension + strlen(extension));

    // 3. Compute hash
    uint8_t verification_hash[32];
    sm3(full_message.data(), full_message.size(), verification_hash);

    std::cout << "Verification hash: ";
    print_hash(verification_hash);

    // Check if they match
    if (memcmp(new_hash, verification_hash, 32) == 0) {
        std::cout << "\nSuccess! The attack produced the correct hash." << std::endl;
    }
    else {
        std::cout << "\nAttack failed! The hashes don't match." << std::endl;
    }

    return 0;
}