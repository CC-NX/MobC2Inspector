/*
 * libnative.so — 原生加密层
 *
 * 功能：
 * 1. AES-128-ECB 加解密（密钥硬编码在 .so 中，隐于 native 层）
 * 2. 通过 JNI 暴露给 Java 调用
 *
 * 密钥硬编码优势：反编译 Java 字节码不可见，需逆向 .so 才能提取
 */

#include <jni.h>
#include <cstring>
#include <cstdlib>
#include <cstdint>
#include <vector>
#include <android/log.h>

#define LOG_TAG "NativeCrypto"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// =====================================================================
//  AES-128 密钥 — 仅存在于 native 层，Java 端不可见
// =====================================================================
// "TestC2Key16Byte!" 的十六进制编码
static const unsigned char AES_KEY[16] = {
    0x54, 0x65, 0x73, 0x74, 0x43, 0x32, 0x4b, 0x65,
    0x79, 0x31, 0x36, 0x42, 0x79, 0x74, 0x65, 0x21
};

// =====================================================================
//  AES-128 标准算法 (FIPS-197)
// =====================================================================

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
};

static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d
};

static const uint8_t RCON[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

static uint8_t xtime(uint8_t a) {
    uint8_t r = (uint8_t)((a << 1) ^ (((a >> 7) & 1) * 0x1b));
    return r;
}

static void key_expansion(const uint8_t key[16], uint8_t rk[176]) {
    for (int i = 0; i < 16; i++) rk[i] = key[i];
    for (int i = 4; i < 44; i++) {
        uint32_t temp = (rk[(i-1)*4] << 24) | (rk[(i-1)*4+1] << 16)
                      | (rk[(i-1)*4+2] << 8) | rk[(i-1)*4+3];
        if (i % 4 == 0) {
            temp = ((SBOX[(temp >> 16) & 0xff] << 24)
                  | (SBOX[(temp >> 8) & 0xff] << 16)
                  | (SBOX[temp & 0xff] << 8)
                  | SBOX[(temp >> 24) & 0xff]) ^ (RCON[i/4] << 24);
        }
        uint32_t prev = (rk[(i-4)*4] << 24) | (rk[(i-4)*4+1] << 16)
                      | (rk[(i-4)*4+2] << 8) | rk[(i-4)*4+3];
        temp ^= prev;
        rk[i*4] = (temp >> 24) & 0xff;
        rk[i*4+1] = (temp >> 16) & 0xff;
        rk[i*4+2] = (temp >> 8) & 0xff;
        rk[i*4+3] = temp & 0xff;
    }
}

static void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = SBOX[state[i]];
}

static void inv_sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) state[i] = INV_SBOX[state[i]];
}

static void shift_rows(uint8_t state[16]) {
    uint8_t tmp;
    tmp = state[1]; state[1] = state[5]; state[5] = state[9];
    state[9] = state[13]; state[13] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[15]; state[15] = state[11];
    state[11] = state[7]; state[7] = tmp;
}

static void inv_shift_rows(uint8_t state[16]) {
    uint8_t tmp;
    tmp = state[13]; state[13] = state[9]; state[9] = state[5];
    state[5] = state[1]; state[1] = tmp;
    tmp = state[2]; state[2] = state[10]; state[10] = tmp;
    tmp = state[6]; state[6] = state[14]; state[14] = tmp;
    tmp = state[3]; state[3] = state[7]; state[7] = state[11];
    state[11] = state[15]; state[15] = tmp;
}

static void mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        state[i]   = (uint8_t)(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        state[i+1] = (uint8_t)(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        state[i+2] = (uint8_t)(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        state[i+3] = (uint8_t)((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
    }
}

static void inv_mix_columns(uint8_t state[16]) {
    for (int c = 0; c < 4; c++) {
        int i = c * 4;
        uint8_t a0 = state[i], a1 = state[i+1], a2 = state[i+2], a3 = state[i+3];
        state[i]   = (uint8_t)(xtime(xtime(xtime(a0)^a0)^a0) ^ xtime(xtime(a1)^a1) ^ a1 ^ xtime(xtime(a2)^a2) ^ a2 ^ xtime(a3) ^ a3);
        state[i+1] = (uint8_t)(xtime(a0) ^ a0 ^ xtime(xtime(xtime(a1)^a1)^a1) ^ xtime(xtime(a2)^a2) ^ a2 ^ xtime(xtime(a3)^a3) ^ a3);
        state[i+2] = (uint8_t)(xtime(a0) ^ a0 ^ xtime(a1) ^ a1 ^ xtime(xtime(xtime(a2)^a2)^a2) ^ xtime(xtime(a3)^a3) ^ a3);
        state[i+3] = (uint8_t)(xtime(xtime(a0)^a0) ^ a0 ^ xtime(a1) ^ a1 ^ xtime(a2) ^ a2 ^ xtime(xtime(xtime(a3)^a3)^a3));
    }
}

static void add_round_key(uint8_t state[16], const uint8_t rk[16]) {
    for (int i = 0; i < 16; i++) state[i] ^= rk[i];
}

static void aes_encrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    add_round_key(state, rk);
    for (int round = 1; round < 10; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, rk + round * 16);
    }
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, rk + 10 * 16);
    memcpy(out, state, 16);
}

static void aes_decrypt_block(const uint8_t in[16], uint8_t out[16], const uint8_t rk[176]) {
    uint8_t state[16];
    memcpy(state, in, 16);
    add_round_key(state, rk + 10 * 16);
    inv_shift_rows(state);
    inv_sub_bytes(state);
    for (int round = 9; round >= 1; round--) {
        add_round_key(state, rk + round * 16);
        inv_mix_columns(state);
        inv_shift_rows(state);
        inv_sub_bytes(state);
    }
    add_round_key(state, rk);
    memcpy(out, state, 16);
}

// =====================================================================
//  PKCS7 填充 / 去填充
// =====================================================================
static std::vector<uint8_t> pkcs7_pad(const uint8_t* data, size_t len) {
    size_t pad_len = 16 - (len % 16);
    std::vector<uint8_t> result(len + pad_len);
    memcpy(result.data(), data, len);
    memset(result.data() + len, (int)pad_len, pad_len);
    return result;
}

static std::vector<uint8_t> pkcs7_unpad(const uint8_t* data, size_t len) {
    if (len == 0 || len % 16 != 0) return {};
    uint8_t pad_val = data[len - 1];
    if (pad_val == 0 || pad_val > 16) return {};
    // 验证所有填充字节
    for (size_t i = len - pad_val; i < len; i++) {
        if (data[i] != pad_val) return {};
    }
    std::vector<uint8_t> result(data, data + len - pad_val);
    return result;
}

// =====================================================================
//  JNI 桥接
// =====================================================================
extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_cc_mumac2_NativeCryptoBridge_encrypt(
    JNIEnv* env, jclass clazz, jbyteArray input)
{
    if (input == nullptr) return nullptr;

    jsize in_len = env->GetArrayLength(input);
    jbyte* in_data = env->GetByteArrayElements(input, nullptr);

    // PKCS7 填充
    std::vector<uint8_t> padded = pkcs7_pad((uint8_t*)in_data, in_len);
    env->ReleaseByteArrayElements(input, in_data, JNI_ABORT);

    // 密钥扩展
    uint8_t rk[176];
    key_expansion(AES_KEY, rk);

    // 逐块加密
    size_t block_count = padded.size() / 16;
    std::vector<uint8_t> out(padded.size());
    for (size_t i = 0; i < block_count; i++) {
        aes_encrypt_block(padded.data() + i * 16, out.data() + i * 16, rk);
    }

    jbyteArray result = env->NewByteArray(out.size());
    env->SetByteArrayRegion(result, 0, out.size(), (jbyte*)out.data());
    return result;
}

extern "C" JNIEXPORT jbyteArray JNICALL
Java_com_cc_mumac2_NativeCryptoBridge_decrypt(
    JNIEnv* env, jclass clazz, jbyteArray input)
{
    if (input == nullptr) return nullptr;

    jsize in_len = env->GetArrayLength(input);
    if (in_len % 16 != 0) return nullptr;

    jbyte* in_data = env->GetByteArrayElements(input, nullptr);

    uint8_t rk[176];
    key_expansion(AES_KEY, rk);

    // 逐块解密
    size_t block_count = in_len / 16;
    std::vector<uint8_t> decrypted(in_len);
    for (size_t i = 0; i < block_count; i++) {
        aes_decrypt_block((uint8_t*)in_data + i * 16,
                          decrypted.data() + i * 16, rk);
    }
    env->ReleaseByteArrayElements(input, in_data, JNI_ABORT);

    // 去填充
    std::vector<uint8_t> result = pkcs7_unpad(decrypted.data(), decrypted.size());
    if (result.empty()) return nullptr;

    jbyteArray jresult = env->NewByteArray(result.size());
    env->SetByteArrayRegion(jresult, 0, result.size(), (jbyte*)result.data());
    return jresult;
}
