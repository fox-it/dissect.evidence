from __future__ import annotations

from dissect.cstruct import cstruct

adcrypt_def = """
#define ADCRYPT_MAGIC ADCRYPT\00

enum EncAlgo : uint32 {
    AES128 = 0x1,
    AES192 = 0x2,
    AES256 = 0x3,
};

enum HashAlgo : uint32 {
    SHA256 = 0x1,
    SHA512 = 0x2,
};

struct Header {
    char        magic[8];           // b"ADCRYPT\x00"
    uint32      version;            // 0x01
    uint32      header_size;        // 0x200 aka offset enc data
    int16       num_passwords;      // always -0x1 ?
    int16       num_raw_keys;       // always -0x1 ?
    int16       num_certificates;   // always -0x1 ?
    char        reserved[2];        // 00 00
    EncAlgo     enc_algo;
    HashAlgo    hash_algo;
    uint32      pbkdf2_count;
    uint32      salt_len;
    uint32      key_len;
    uint32      hmac_len;
    char        enc_salt[salt_len];
    char        enc_key[key_len];
    char        hmac_enc_key[hmac_len];
    // padding until 0x200
};
"""

c_adcrypt = cstruct().load(adcrypt_def)
