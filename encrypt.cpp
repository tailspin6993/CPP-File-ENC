#include <cstring>
#include <iostream>
#include <fstream>
#include <sodium.h>
#include <sodium/crypto_generichash_blake2b.h>
#include <sodium/utils.h>

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

    unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
    randombytes_buf(salt, sizeof salt);
    
    char password[32];
    std::cout << "Password (max of 32 chars): ";
    std::cin.getline(password, 32);

    const std::size_t fullKeyLength = 
        crypto_stream_xchacha20_KEYBYTES + crypto_generichash_blake2b_KEYBYTES;
    
    unsigned char fullKey[fullKeyLength];
    int hashStatus = crypto_pwhash(
        fullKey, 
        sizeof fullKey,
        password, 
        strlen(password), 
        salt,
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE,
        crypto_pwhash_ALG_ARGON2ID13
    );

    unsigned char key[crypto_stream_xchacha20_KEYBYTES];
    unsigned char macKey[crypto_generichash_blake2b_KEYBYTES];

    splitFullKey(fullKey, key, sizeof key, macKey, sizeof macKey);
    sodium_memzero(fullKey, sizeof fullKey);

    // zero-out password ASAP.
    sodium_memzero(password, sizeof password);

    if (hashStatus != 0) {
        std::cout << "Key derivation failed." << std::endl;
        return 1;
    }

    unsigned char masterFullKey[fullKeyLength];
    randombytes_buf(masterFullKey, sizeof masterFullKey);

    unsigned char masterEncKey[sizeof key];
    unsigned char masterMacKey[sizeof macKey];

    splitFullKey(masterFullKey, masterEncKey, sizeof masterEncKey, masterMacKey, sizeof masterMacKey);

    unsigned char masterKeyNonce[crypto_stream_xchacha20_NONCEBYTES];
    unsigned char dataNonce[crypto_stream_xchacha20_NONCEBYTES];

    randombytes_buf(masterKeyNonce, sizeof masterKeyNonce);
    randombytes_buf(dataNonce, sizeof dataNonce);

    const std::size_t CHUNK_SIZE = 1024;
    unsigned char buff[CHUNK_SIZE];

    std::ifstream inFile(fileName, std::ios::binary);
    std::ofstream outFile(fileName + "_enc", std::ios::binary);

    crypto_stream_xchacha20_xor(masterFullKey, masterFullKey, sizeof masterFullKey, masterKeyNonce, key);
    sodium_memzero(key, sizeof key);

    unsigned char masterFullKeyDigest[crypto_generichash_blake2b_BYTES];
    crypto_generichash_blake2b(masterFullKeyDigest, sizeof masterFullKeyDigest, masterFullKey, sizeof masterFullKey, macKey, sizeof macKey);

    sodium_memzero(macKey, sizeof macKey);

    outFile.write(reinterpret_cast<char*>(&dataNonce), sizeof dataNonce);
    outFile.write(reinterpret_cast<char*>(&masterKeyNonce), sizeof masterKeyNonce);
    outFile.write(reinterpret_cast<char*>(&salt), sizeof salt);
    outFile.write(reinterpret_cast<char*>(&masterFullKeyDigest), sizeof masterFullKeyDigest);
    outFile.write(reinterpret_cast<char*>(&masterFullKey), sizeof masterFullKey);

    sodium_memzero(salt, sizeof salt);
    sodium_memzero(masterFullKey, sizeof masterFullKey);
    sodium_memzero(masterKeyNonce, sizeof masterKeyNonce);
    sodium_memzero(masterFullKeyDigest, sizeof masterFullKeyDigest);

    while (inFile) {
        inFile.read(reinterpret_cast<char*>(&buff), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            crypto_stream_xchacha20_xor(buff, buff, sizeof buff, dataNonce, masterEncKey);

            unsigned char byteBlockDigest[crypto_generichash_blake2b_BYTES];
            crypto_generichash_blake2b(byteBlockDigest, sizeof byteBlockDigest, buff, bytesRead, masterMacKey, sizeof masterMacKey);

            outFile.write(reinterpret_cast<char*>(&byteBlockDigest), sizeof byteBlockDigest);
            outFile.write(reinterpret_cast<char*>(&buff), bytesRead);

            sodium_memzero(buff, sizeof buff);
            sodium_memzero(byteBlockDigest, sizeof byteBlockDigest);
        }
    }

    sodium_memzero(masterEncKey, sizeof masterEncKey);
    sodium_memzero(masterMacKey, sizeof masterMacKey);
    sodium_memzero(dataNonce, sizeof dataNonce);

    inFile.close();
    outFile.close();
}
