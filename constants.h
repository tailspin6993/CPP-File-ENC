#ifndef CONSTANTS_H
#define CONSTANTS_H

const int ENCRYPTION_KEY_LENGTH = 32;
const int MAC_KEY_LENGTH = 32;
const int NONCE_LENGTH = 24;
const int SALT_LENGTH = 16;

const int FULL_KEY_LENGTH = 
    ENCRYPTION_KEY_LENGTH + MAC_KEY_LENGTH;
    
const int DIGEST_SIZE = 32;
const int CHUNK_SIZE = 1024;

#endif