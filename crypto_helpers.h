#ifndef CRYPTOHELPERS_H
#define CRYPTOHELPERS_H

namespace CryptoHelpers {
    extern const int ENCRYPTION_KEY_LENGTH;
    extern const int MAC_KEY_LENGTH;
    extern const int NONCE_LENGTH;
    extern const int SALT_LENGTH;

    extern const int FULL_KEY_LENGTH;
        
    extern const int DIGEST_SIZE;
    extern const int CHUNK_SIZE;

    void splitFullKey(unsigned char* fullKey, unsigned char* encryptionKey, int encryptionKeyLen, unsigned char* macKey, int macKeyLen);
    int deriveFullKey(unsigned char* out, int outLen, char* password, int passwordLen, unsigned char* salt);
}

#endif