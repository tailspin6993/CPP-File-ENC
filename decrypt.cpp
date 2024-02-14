#include <cstring>
#include <iostream>
#include <fstream>
#include <sodium.h>

#include "constants.h"

void splitFullKey(unsigned char* fullKey, unsigned char* encryptionKey, int encryptionKeyLen, unsigned char* macKey, int macKeyLen) {
    for (int i = 0; i < encryptionKeyLen; i++) {
        encryptionKey[i] = fullKey[i];
    }

    for (int i = 0; i < macKeyLen; i++)
        macKey[i] = fullKey[i + encryptionKeyLen];
}

int main() {
    if (sodium_init() > 0) 
        std::cout << "Libsodium failed to initialize." << std::endl;
        
    std::string fileName;
    std::cout << "File to decrypt: ";
    getline(std::cin, fileName);
    
    char password[32];
    std::cout << "Password (max of 32 chars): ";
    std::cin.getline(password, 32);

    unsigned char buff[CHUNK_SIZE];

    std::ifstream inFile(fileName, std::ios::binary);

    unsigned char masterKeyNonce[NONCE_LENGTH];
    unsigned char dataNonce[NONCE_LENGTH];
    unsigned char salt[SALT_LENGTH];
    unsigned char masterKeyDigest[DIGEST_SIZE];
    unsigned char masterKey[FULL_KEY_LENGTH];

    int seekPos = 0;

    if (inFile) {
        inFile.read(reinterpret_cast<char*>(dataNonce), sizeof dataNonce);
        seekPos += sizeof dataNonce;
        inFile.seekg(seekPos);

        inFile.read(reinterpret_cast<char*>(masterKeyNonce), sizeof masterKeyNonce);
        seekPos += sizeof masterKeyNonce;
        inFile.seekg(seekPos);

        inFile.read(reinterpret_cast<char*>(salt), sizeof salt);
        seekPos += sizeof salt;
        inFile.seekg(seekPos);

        inFile.read(reinterpret_cast<char*>(masterKeyDigest), sizeof masterKeyDigest);
        seekPos += sizeof masterKeyDigest;
        inFile.seekg(seekPos);

        inFile.read(reinterpret_cast<char*>(masterKey), sizeof masterKey);
        seekPos += sizeof masterKey;
        inFile.seekg(seekPos);
    }
    
    unsigned char key[FULL_KEY_LENGTH];
    int hashStatus = crypto_pwhash(
        key, 
        sizeof key,
        password,
        strlen(password), 
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    if (hashStatus != 0) {
        std::cout << "Key derivation failed." << std::endl;
        return 1;
    }

    unsigned char userEncKey[ENCRYPTION_KEY_LENGTH];
    unsigned char userMacKey[MAC_KEY_LENGTH];

    splitFullKey(key, userEncKey, sizeof userEncKey, userMacKey, sizeof userMacKey);
    sodium_memzero(key, sizeof key);

    unsigned char computedMasterKeyDigest[DIGEST_SIZE];
    crypto_generichash_blake2b(computedMasterKeyDigest, sizeof computedMasterKeyDigest, masterKey, sizeof masterKey, userMacKey, sizeof userMacKey);

    if (sodium_memcmp(computedMasterKeyDigest, masterKeyDigest, sizeof computedMasterKeyDigest) != 0) {
        std::cout << "Incorrect password." << std::endl;
        return 1;
    }

    crypto_stream_xchacha20_xor(masterKey, masterKey, sizeof masterKey, masterKeyNonce, userEncKey);

    unsigned char masterEncKey[ENCRYPTION_KEY_LENGTH];
    unsigned char masterMacKey[MAC_KEY_LENGTH];

    splitFullKey(masterKey, masterEncKey, sizeof masterEncKey, masterMacKey, sizeof masterMacKey);

    // zero-out password ASAP.
    sodium_memzero(password, sizeof password);
    sodium_memzero(key, sizeof key);
    sodium_memzero(userEncKey, sizeof userEncKey);
    sodium_memzero(userMacKey, sizeof userMacKey);

    std::ofstream outFile(fileName + "_dec", std::ios::binary);

    while (inFile) {
        unsigned char byteBlockDigest[DIGEST_SIZE];
        inFile.read(reinterpret_cast<char*>(&byteBlockDigest), DIGEST_SIZE);
        inFile.read(reinterpret_cast<char*>(&buff), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            unsigned char computedByteBlockDigest[DIGEST_SIZE];
            crypto_generichash_blake2b(computedByteBlockDigest, sizeof computedByteBlockDigest, buff, bytesRead, masterMacKey, sizeof masterMacKey);

            if (sodium_memcmp(byteBlockDigest, computedByteBlockDigest, sizeof computedByteBlockDigest) != 0) {
                std::cout << "MAC verification failed for byte block." << std::endl;
                return 1;
            }

            crypto_stream_xchacha20_xor(buff, buff, sizeof buff, dataNonce, masterKey);
            outFile.write(reinterpret_cast<char*>(&buff), bytesRead);

            sodium_memzero(buff, sizeof buff);
            sodium_memzero(byteBlockDigest, sizeof byteBlockDigest);
            sodium_memzero(computedByteBlockDigest, sizeof computedByteBlockDigest);
        }
    }

    sodium_memzero(masterKey, sizeof masterKey);

    inFile.close();
    outFile.close();

    sodium_memzero(masterKeyNonce, sizeof masterKeyNonce);
    sodium_memzero(dataNonce, sizeof dataNonce);
    sodium_memzero(salt, sizeof salt);
    sodium_memzero(buff, sizeof buff);

    std::cout << "Successfully decrypted." << std::endl;
}
