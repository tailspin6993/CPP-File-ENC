#include <sodium.h>
#include <cstring>
#include <sodium/crypto_pwhash_argon2id.h>

#include "crypto_helpers.h"

const int CryptoHelpers::ENCRYPTION_KEY_LENGTH = crypto_stream_xchacha20_KEYBYTES;
const int CryptoHelpers::MAC_KEY_LENGTH = crypto_generichash_blake2b_KEYBYTES;
const int CryptoHelpers::NONCE_LENGTH = crypto_stream_xchacha20_NONCEBYTES;
const int CryptoHelpers::SALT_LENGTH = crypto_pwhash_argon2id_SALTBYTES;

const int CryptoHelpers::FULL_KEY_LENGTH = 
    CryptoHelpers::ENCRYPTION_KEY_LENGTH + CryptoHelpers::MAC_KEY_LENGTH;
    
const int CryptoHelpers::DIGEST_SIZE = crypto_generichash_blake2b_BYTES;
const int CryptoHelpers::CHUNK_SIZE = 1024;

void CryptoHelpers::splitFullKey(unsigned char* fullKey, unsigned char* encryptionKey, int encryptionKeyLen, unsigned char* macKey, int macKeyLen) {
    for (int i = 0; i < encryptionKeyLen; i++) {
        encryptionKey[i] = fullKey[i];
    }

    for (int i = 0; i < macKeyLen; i++)
        macKey[i] = fullKey[i + encryptionKeyLen];
}

int CryptoHelpers::deriveFullKey(unsigned char* out, int outLen, char* password, int passwordLen, unsigned char* salt) {
    return crypto_pwhash(
        out, 
        outLen,
        password, 
        strlen(password), 
        salt,
        crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE,
        crypto_pwhash_MEMLIMIT_SENSITIVE,
        crypto_pwhash_ALG_ARGON2ID13
    );
}