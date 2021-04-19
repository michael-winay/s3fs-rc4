#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>

#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

using namespace std;

#define READ_SIZE (1024)

int encryptio (int fd, int enc)
{    
    //encryption variables
    char header[] = "Salted__";
    int inlen, outlen, templen;
    int keylen = EVP_CIPHER_key_length(EVP_rc4());
    unsigned char saltbuffer[8];
    unsigned char fdbuffer_in[READ_SIZE];
    unsigned char fdbuffer_out[READ_SIZE + EVP_MAX_BLOCK_LENGTH];

    //set up encryption key and salt
    //***change passphrase here***
    char passphrase[] = "password";
    unsigned char key[keylen];

    //generate salt
    if(enc == 1) {
        if(RAND_bytes(saltbuffer, 8) == 0) {
            cout << "Error generating salt" << endl;
           return 0;
        }
    }
    //read salt
    else if(enc == 0) {
        if(pread(fd, saltbuffer, sizeof(saltbuffer), sizeof(header) - 1) == -1) {
            cout << "Error reading salt" << endl;
            return 0;
        }
    }
    else {
        cout << "enc must be 0 or 1" << endl;
        return 0;
    }

    //create cipher key
    RC4_KEY rc4key;
    EVP_BytesToKey(EVP_rc4(), EVP_sha256(), saltbuffer, (const unsigned char *)passphrase, strlen(passphrase), 1, key, NULL);
    RC4_set_key(&rc4key, keylen, key);

    //create temp file for storing cipher text, set it to delete after closure of fdcipher
    char cipherTemplate[] = "/tmp/cipherXXXXXX";
    int fdcipher = mkstemp(cipherTemplate);
    if (fdcipher == -1) {
        cout << "Error creating cipher temp file" << endl;
        return 0;
    }
    unlink(cipherTemplate);

    //write salt to beginning
    if (enc == 1) {
        inlen = pwrite(fdcipher, header, sizeof(header) - 1, 0);
        inlen = pwrite(fdcipher, saltbuffer, sizeof(saltbuffer), sizeof(header) - 1);

        if (inlen == -1) {
            cout << "Error writing salt to file" << endl;
            return 0;
        }
    }

    //encrypt/ decrypt file, write encrypted text to temp file
    for(int i = 0; i >= 0; i++) {

        //if the file is being decrypted, then the salt at the beginning has already been handled at this point, and the first 16? characters are ignored
        if(enc == 1) inlen = pread(fd, fdbuffer_in, READ_SIZE, i * READ_SIZE);
        if(enc == 0) inlen = pread(fd, fdbuffer_in, READ_SIZE, (i* READ_SIZE) + ((sizeof(header) - 1) + sizeof(saltbuffer)));

        if (inlen == -1) {
            cout << "Error reading file for encryption" << endl;
            return 0;
        }

        //encrypt/ decrypt with RC4
        RC4(&rc4key, inlen, fdbuffer_in, fdbuffer_out);

        if(enc == 1) templen = pwrite(fdcipher, fdbuffer_out, inlen, (i* READ_SIZE) + ((sizeof(header) - 1) + sizeof(saltbuffer)));
        if(enc == 0) templen = pwrite(fdcipher, fdbuffer_out, inlen, i * READ_SIZE);
        if(templen == -1) {
            cout << "Error writing to file from encryption" << endl;
            return 0;
        }

        if (inlen < READ_SIZE) {
            ftruncate(fd, 0);
            break;
        }
    }

    //write data from temp file back to main file
    for(int i = 0; i >= 0; i++) {
        inlen = pread(fdcipher, fdbuffer_out, READ_SIZE, i * READ_SIZE);
        if (inlen == -1) {
            cout << "Error reading from cipher temp file" << endl;
            close(fdcipher);
            return 0;
        }
        outlen = pwrite(fd, fdbuffer_out, inlen, i * READ_SIZE);
        if (outlen == -1) {
            cout << "Error writing from cipher temp file" << endl;
            close(fdcipher);
            return 0;
        }
        if (inlen < READ_SIZE) {
            break;
        }
    }
    //free cipher memory
    return 1;
}