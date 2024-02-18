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
    std::cout << "File to encrypt: ";
    getline(std::cin, fileName);

    std::ifstream inFile(fileName, std::ios::binary);

    if(!inFile) {
        std::cout << "File not found" << std::endl;
        return 1;
    }
    
    char password[32];
    std::cout << "Password (max of 32 chars): ";
    std::cin.getline(password, 32);

    unsigned char salt[SALT_LENGTH];
    randombytes_buf(salt, sizeof salt);
    
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

    // zero-out password ASAP.
    sodium_memzero(password, sizeof password);

    unsigned char masterFullKey[FULL_KEY_LENGTH];

    unsigned char masterEncKey[ENCRYPTION_KEY_LENGTH];
    unsigned char masterMacKey[MAC_KEY_LENGTH];

    unsigned char masterKeyNonce[NONCE_LENGTH];

    randombytes_buf(masterFullKey, sizeof masterFullKey);
    randombytes_buf(masterKeyNonce, sizeof masterKeyNonce);

    splitFullKey(masterFullKey, masterEncKey, sizeof masterEncKey, masterMacKey, sizeof masterMacKey);

    std::ofstream outFile(fileName + "_enc", std::ios::binary);

    crypto_stream_xchacha20_xor(masterFullKey, masterFullKey, sizeof masterFullKey, masterKeyNonce, userEncKey);
    sodium_memzero(userEncKey, sizeof userEncKey);

    unsigned char masterFullKeyDigest[crypto_generichash_blake2b_BYTES];
    crypto_generichash_blake2b(masterFullKeyDigest, sizeof masterFullKeyDigest, masterFullKey, sizeof masterFullKey, userMacKey, sizeof userMacKey);

    sodium_memzero(userMacKey, sizeof userMacKey);

    outFile.write(reinterpret_cast<char*>(&masterKeyNonce), sizeof masterKeyNonce);
    outFile.write(reinterpret_cast<char*>(&salt), sizeof salt);
    outFile.write(reinterpret_cast<char*>(&masterFullKeyDigest), sizeof masterFullKeyDigest);
    outFile.write(reinterpret_cast<char*>(&masterFullKey), sizeof masterFullKey);

    sodium_memzero(salt, sizeof salt);
    sodium_memzero(masterFullKey, sizeof masterFullKey);
    sodium_memzero(masterKeyNonce, sizeof masterKeyNonce);
    sodium_memzero(masterFullKeyDigest, sizeof masterFullKeyDigest);

    unsigned char buff[CHUNK_SIZE];
    unsigned char dataNonce[NONCE_LENGTH];

    while (inFile) {
        randombytes_buf(dataNonce, sizeof dataNonce);
        inFile.read(reinterpret_cast<char*>(&buff), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            crypto_stream_xchacha20_xor(buff, buff, sizeof buff, dataNonce, masterEncKey);

            unsigned char byteBlockDigest[DIGEST_SIZE];

            crypto_generichash_blake2b_state state;
            crypto_generichash_blake2b_init(&state, masterMacKey, sizeof masterMacKey, sizeof byteBlockDigest);

            crypto_generichash_blake2b_update(&state, dataNonce, sizeof dataNonce);
            crypto_generichash_blake2b_update(&state, buff, bytesRead);

            crypto_generichash_blake2b_final(&state, byteBlockDigest, sizeof byteBlockDigest);

            outFile.write(reinterpret_cast<char*>(&byteBlockDigest), sizeof byteBlockDigest);
            outFile.write(reinterpret_cast<char*>(&dataNonce), sizeof dataNonce);
            outFile.write(reinterpret_cast<char*>(&buff), bytesRead);

            sodium_memzero(byteBlockDigest, sizeof byteBlockDigest);
            sodium_memzero(dataNonce, sizeof dataNonce);
            sodium_memzero(buff, sizeof buff);
        }
    }

    sodium_memzero(masterEncKey, sizeof masterEncKey);
    sodium_memzero(masterMacKey, sizeof masterMacKey);
    sodium_memzero(dataNonce, sizeof dataNonce);

    inFile.close();
    outFile.close();
}
