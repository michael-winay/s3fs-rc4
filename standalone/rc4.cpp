#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <iostream>
#include <string.h>

#include <openssl/rc4.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

using namespace std;

#define READ_SIZE (1024)

int main(int argc, char* argv[]) {
    //pre-argument variables
    char *password, *infile, *outfile;
    bool enc = false, dec = false, in = false, out = false, k = false, salt = false, nosalt = false;

    //argument setting
    for (int i = 1; i < argc; i++) {
        if(!strcmp(argv[i],"-e")) {
            enc = true;
            continue;
        }
        if(!strcmp(argv[i],"-d")) {
            dec = true;
            continue;
        }
        if(!strcmp(argv[i],"-in")) {
            infile = (char *)argv[++i];
            in = true;
            continue;
        }
        if(!strcmp(argv[i],"-out")) {
            outfile = (char *)argv[++i];
            out = true;
            continue;
        }
        if(!strcmp(argv[i],"-k")) {
            password = (char *)argv[++i];
            k = true;
            continue;
        }
        if(!strcmp(argv[i],"-salt")) {
            salt = true;
            continue;
        }
        if(!strcmp(argv[i],"-nosalt")) {
            nosalt = true;
            continue;
        }
        else {
            cout << argv[i] << " flag not recognized, resuming..." << endl;
            continue;
        }
    }
    //default arguments set
    if (salt == false && nosalt == false) {
        salt = true;
    }

    //argument exceptions
    if((enc == true && dec == true) || (enc == false && dec == false)) {
        cout << "Please provide either -e or -d argument" << endl;
        return 0;
    }

    if(salt == true && nosalt == true) {
        cout << "Cannot take -nosalt and -salt arguments" << endl;
        return 0;
    }

    if(in == false) {
        cout << "Please provide an input file" << endl;
        return 0;
    }

    //encryption variables
    char header[] = "Salted__";
    int inlen, outlen, templen;
    int keylen = EVP_CIPHER_key_length(EVP_rc4());
    unsigned char saltbuffer[8];
    unsigned char fdbuffer_in[READ_SIZE];
    unsigned char fdbuffer_out[READ_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char key[keylen];
    const char *passphrase;
    RC4_KEY rc4key;


        //fix this tomorrow. passphrase should function similar to the s3fs one
    //assign passphrase
    if(k == true) {
        passphrase = password;
    }
    else {
        string passtemp;
        cout << "Enter password: ";
        cin >> passtemp;
        passphrase = passtemp.c_str();
    }

    //create file descriptors
    int fd_in = open(infile, O_RDONLY);
    if(out == false) {
        outfile = "output";
    }
    int fd_out = open(outfile, O_WRONLY | O_CREAT, 0666);

    //generate salt
    if(enc == true && salt == true) {
        if(RAND_bytes(saltbuffer, 8) == 0) {
            cout << "Error generating salt" << endl;
           return 0;
        }
    }
    //read salt
    else if(dec == true && salt == true) {
        if(pread(fd_in, saltbuffer, sizeof(saltbuffer), sizeof(header) - 1) == -1) {
            cout << "Error reading salt" << endl;
            return 0;
        }
    }
    //write salt to beginning
    if (enc == true && salt == true) {
        inlen = pwrite(fd_out, header, sizeof(header) - 1, 0);
        inlen = pwrite(fd_out, saltbuffer, sizeof(saltbuffer), sizeof(header) - 1);

        if (inlen == -1) {
            cout << "Error writing salt to file" << endl;
            return 0;
        }
    }
    //create cipher key: salt
    if (salt == true) {
        EVP_BytesToKey(EVP_rc4(), EVP_sha256(), saltbuffer, (const unsigned char *)passphrase, strlen(passphrase), 1, key, NULL);
        RC4_set_key(&rc4key, keylen, key);
    }
    //create cipher key: nosalt
    if (nosalt == true) {
        EVP_BytesToKey(EVP_rc4(), EVP_sha256(), NULL, (const unsigned char *)passphrase, strlen(passphrase), 1, key, NULL);
        RC4_set_key(&rc4key, keylen, key);
    }

    //encrypt/ decrypt file, write output to output file
    for(int i = 0; i >= 0; i++) {

        //read for encryption OR read for decryption: nosalt
        if(enc == true || nosalt == true) inlen = pread(fd_in, fdbuffer_in, READ_SIZE, i * READ_SIZE);

        //read for decryption: salt
        if(dec == true && salt == true) inlen = pread(fd_in, fdbuffer_in, READ_SIZE, (i* READ_SIZE) + ((sizeof(header) - 1) + sizeof(saltbuffer)));

        if (inlen == -1) {
            cout << "Error reading file for encryption" << endl;
            return 0;
        }

        //encrypt/ decrypt with RC4
        RC4(&rc4key, inlen, fdbuffer_in, fdbuffer_out);

        //write to output file: salted encrypted
        if(enc == true && salt == true) templen = pwrite(fd_out, fdbuffer_out, inlen, (i* READ_SIZE) + ((sizeof(header) - 1) + sizeof(saltbuffer)));

        //write to output file: decrypted
        if(dec == true || nosalt == true) templen = pwrite(fd_out, fdbuffer_out, inlen, i * READ_SIZE);

        if(templen == -1) {
            cout << "Error writing to file from encryption" << endl;
            return 0;
        }

        if (inlen < READ_SIZE) {
            break;
        }
    }
    //free cipher memory
    return 1;
}