#include<openssl/evp.h>
#include<openssl/pem.h>
#include<openssl/err.h>
#include<iostream>

using namespace std;


/* Function to encrypt a message using RSA public key */
bool rsaEncrypt(const unsigned char* plaintext, size_t plaintextLen, EVP_PKEY* publicKey, unsigned char* ciphertext, size_t& ciphertextLen)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(publicKey, nullptr);
    if(!ctx)
    {
        cerr << "Error creating EVP_PKEY_CTX." << endl;
        return false;
    }

    if(EVP_PKEY_encrypt_init(ctx) <= 0)
    {
        cerr << "Error initializing EVP_PKEY_CTX for encryption." << endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if(EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0)
    {
        cerr << "Error setting RSA padding mode." << endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_encrypt(ctx, ciphertext, &ciphertextLen, plaintext, plaintextLen) <= 0)
    {
        cerr << "Error encrypting data." << endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

/* Function to decrypt ciphertext using RSA private key */ 
bool rsaDecrypt(const unsigned char* ciphertext, size_t ciphertextLen, EVP_PKEY* privateKey, unsigned char* plaintext, size_t& plaintextLen)
{
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(privateKey, nullptr);
    if (!ctx) {
        cerr << "Error creating EVP_PKEY_CTX." << endl;
        return false;
    }

    if (EVP_PKEY_decrypt_init(ctx) <= 0) {
        cerr << "Error initializing EVP_PKEY_CTX for decryption." << endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0) {
        cerr << "Error setting RSA padding mode." << endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    if (EVP_PKEY_decrypt(ctx, plaintext, &plaintextLen, ciphertext, ciphertextLen) <= 0) {
        cerr << "Error decrypting data." << endl;
        
        /* Retrieve and print the error information */ 
        unsigned long errCode = ERR_get_error();
        char errBuff[256];
        ERR_error_string_n(errCode, errBuff, sizeof(errBuff));
        cerr << "Error code: " << errCode << endl;
        cerr << "Error message: " << errBuff << endl;

        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}