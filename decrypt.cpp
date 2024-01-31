#include <cstring>
#include <iostream>
#include <fstream>
#include <sodium.h>

int main() {
    if (sodium_init() > 0) 
        std::cout << "Libsodium failed to initialize." << std::endl;
        
    std::string fileName;
    std::cout << "File to decrypt: ";
    getline(std::cin, fileName);
    
    char password[32];
    std::cout << "Password (max of 32 chars): ";
    std::cin.getline(password, 32);

    const std::size_t CHUNK_SIZE = 1024;
    unsigned char buff[CHUNK_SIZE];

    std::ifstream inFile(fileName, std::ios::binary);
    std::ofstream outFile(fileName + "_dec", std::ios::binary);

    unsigned char masterKeyNonce[crypto_stream_xchacha20_NONCEBYTES];
    unsigned char dataNonce[crypto_stream_xchacha20_NONCEBYTES];
    unsigned char salt[crypto_pwhash_argon2id_SALTBYTES];
    unsigned char masterKey[crypto_stream_xchacha20_KEYBYTES];

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

        inFile.read(reinterpret_cast<char*>(masterKey), sizeof masterKey);
        seekPos += sizeof masterKey;
        inFile.seekg(seekPos);
    }
    
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

    crypto_stream_xchacha20_xor(masterKey, masterKey, sizeof masterKey, masterKeyNonce, key);
    sodium_memzero(key, sizeof key);

    while (inFile) {
        inFile.read(reinterpret_cast<char*>(&buff), CHUNK_SIZE);
        std::streamsize bytesRead = inFile.gcount();

        if (bytesRead > 0) {
            crypto_stream_xchacha20_xor(buff, buff, sizeof buff, dataNonce, masterKey);
            outFile.write(reinterpret_cast<char*>(&buff), bytesRead);

            sodium_memzero(buff, sizeof buff);
        }
    }

    sodium_memzero(masterKey, sizeof masterKey);

    inFile.close();
    outFile.close();

    sodium_memzero(masterKeyNonce, sizeof masterKeyNonce);
    sodium_memzero(dataNonce, sizeof dataNonce);
    sodium_memzero(salt, sizeof salt);
    sodium_memzero(buff, sizeof buff);
}
