#include <cstring>
#include <iostream>
#include <fstream>
#include <sodium.h>

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

    unsigned char key[crypto_stream_xchacha20_KEYBYTES];
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

    // zero-out password ASAP.
    sodium_memzero(password, sizeof password);

    if (hashStatus != 0) {
        std::cout << "Key derivation failed." << std::endl;
        return 1;
    }

    unsigned char masterKey[crypto_stream_xchacha20_KEYBYTES];
    unsigned char masterKeyNonce[crypto_stream_xchacha20_NONCEBYTES];
    unsigned char dataNonce[crypto_stream_xchacha20_NONCEBYTES];

    randombytes_buf(masterKey, sizeof masterKey);
    randombytes_buf(masterKeyNonce, sizeof masterKeyNonce);
    randombytes_buf(dataNonce, sizeof dataNonce);

    const std::size_t CHUNK_SIZE = 1024;
    unsigned char buff[CHUNK_SIZE];

    std::ifstream inFile(fileName, std::ios::binary);
    std::ofstream outFile(fileName + "_enc", std::ios::binary);

    while (inFile) {
        inFile.read(reinterpret_cast<char*>(&buff), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            crypto_stream_xchacha20_xor(buff, buff, sizeof buff, dataNonce, masterKey);
            outFile.write(reinterpret_cast<char*>(&buff), bytesRead);

            sodium_memzero(buff, sizeof buff);
        }
    }

    inFile.close();

    crypto_stream_xchacha20_xor(masterKey, masterKey, sizeof masterKey, masterKeyNonce, key);
    outFile.write(reinterpret_cast<char*>(&dataNonce), sizeof dataNonce);
    outFile.write(reinterpret_cast<char*>(&masterKeyNonce), sizeof masterKeyNonce);
    outFile.write(reinterpret_cast<char*>(&salt), sizeof salt);
    outFile.write(reinterpret_cast<char*>(&masterKey), sizeof masterKey);

    outFile.close();

    sodium_memzero(key, sizeof key);
    sodium_memzero(masterKeyNonce, sizeof masterKeyNonce);
    sodium_memzero(dataNonce, sizeof dataNonce);
    sodium_memzero(salt, sizeof salt);
    sodium_memzero(masterKey, sizeof masterKey);
    sodium_memzero(buff, sizeof buff);
}
