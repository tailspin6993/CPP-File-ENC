#include <cstring>
#include <iostream>
#include <fstream>
#include <sodium.h>
#include <sodium/utils.h>

#include "crypto_helpers.h"

void writeEncryptedFile(std::ifstream &inFile, std::ofstream &outFile, unsigned char* masterFullKey, int masterFullKeyLen) {
    unsigned char dataNonce[CryptoHelpers::NONCE_LENGTH];
    unsigned char buff[CryptoHelpers::CHUNK_SIZE];
    unsigned char masterEncKey[CryptoHelpers::ENCRYPTION_KEY_LENGTH];
    unsigned char masterMacKey[CryptoHelpers::MAC_KEY_LENGTH];

    CryptoHelpers::splitFullKey(masterFullKey, masterEncKey, sizeof masterEncKey, masterMacKey, sizeof masterMacKey);

    while (inFile) {
        randombytes_buf(dataNonce, sizeof dataNonce);
        inFile.read(reinterpret_cast<char*>(&buff), CryptoHelpers::CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            crypto_kdf_hkdf_sha512_extract(masterFullKey, masterEncKey, sizeof masterEncKey, masterMacKey, sizeof masterMacKey);
            CryptoHelpers::splitFullKey(masterFullKey, masterEncKey, sizeof masterEncKey, masterMacKey, sizeof masterMacKey);

            crypto_stream_xchacha20_xor(buff, buff, sizeof buff, dataNonce, masterEncKey);

            unsigned char byteBlockDigest[CryptoHelpers::DIGEST_SIZE];

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
}

int main() {
    if (sodium_init() == -1) {
        std::cout << "Libsodium failed to initialize." << std::endl;
        return 1;
    }

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

    unsigned char salt[CryptoHelpers::SALT_LENGTH];
    randombytes_buf(salt, sizeof salt);
    
    unsigned char key[CryptoHelpers::FULL_KEY_LENGTH];
    int hashStatus = CryptoHelpers::deriveFullKey(key, sizeof key, password, sizeof password, salt);

    if (hashStatus != 0) {
        std::cout << "Key derivation failed." << std::endl;
        return 1;
    }

    unsigned char userEncKey[CryptoHelpers::ENCRYPTION_KEY_LENGTH];
    unsigned char userMacKey[CryptoHelpers::MAC_KEY_LENGTH];

    CryptoHelpers::splitFullKey(key, userEncKey, sizeof userEncKey, userMacKey, sizeof userMacKey);
    sodium_memzero(key, sizeof key);

    // zero-out password ASAP.
    sodium_memzero(password, sizeof password);

    unsigned char masterFullKey[CryptoHelpers::FULL_KEY_LENGTH];
    unsigned char masterKeyNonce[CryptoHelpers::NONCE_LENGTH];

    randombytes_buf(masterFullKey, sizeof masterFullKey);
    randombytes_buf(masterKeyNonce, sizeof masterKeyNonce);

    std::ofstream outFile(fileName + "_enc", std::ios::binary);

    crypto_stream_xchacha20_xor(masterFullKey, masterFullKey, sizeof masterFullKey, masterKeyNonce, userEncKey);

    unsigned char masterFullKeyDigest[crypto_generichash_blake2b_BYTES];
    crypto_generichash_blake2b_state state;
    
    crypto_generichash_blake2b_init(&state, userMacKey, sizeof userMacKey, sizeof masterFullKeyDigest);
    crypto_generichash_blake2b_update(&state, masterKeyNonce, sizeof masterKeyNonce);
    crypto_generichash_blake2b_update(&state, masterFullKey, sizeof masterFullKey);
    crypto_generichash_blake2b_final(&state, masterFullKeyDigest, sizeof masterFullKeyDigest);

    outFile.write(reinterpret_cast<char*>(&salt), sizeof salt);
    outFile.write(reinterpret_cast<char*>(&masterFullKeyDigest), sizeof masterFullKeyDigest);
    outFile.write(reinterpret_cast<char*>(&masterKeyNonce), sizeof masterKeyNonce);
    outFile.write(reinterpret_cast<char*>(&masterFullKey), sizeof masterFullKey);

    crypto_stream_xchacha20_xor(masterFullKey, masterFullKey, sizeof masterFullKey, masterKeyNonce, userEncKey);
    sodium_memzero(userEncKey, sizeof userEncKey);
    sodium_memzero(userMacKey, sizeof userMacKey);

    sodium_memzero(salt, sizeof salt);
    sodium_memzero(masterKeyNonce, sizeof masterKeyNonce);
    sodium_memzero(masterFullKeyDigest, sizeof masterFullKeyDigest);

    writeEncryptedFile(inFile, outFile, masterFullKey, sizeof masterFullKey);

    inFile.close();
    outFile.close();

    std::cout << "Done encrypting file" << std::endl;
}
