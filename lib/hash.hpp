#include<openssl/evp.h>
#include<stdexcept>

using namespace std;

string SHA256WithSalt(const string& data, const unsigned char* salt, size_t saltSize)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        /* Handle error in context creation */ 
        throw runtime_error("Error creating EVP_MD_CTX.");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        /* Handle error in digest initialization */ 
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Error initializing digest.");
    }

    if (EVP_DigestUpdate(ctx, salt, saltSize) != 1) {
        /* Handle error in digest update */ 
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Error updating digest.");
    }

    if (EVP_DigestUpdate(ctx, data.c_str(), data.size()) != 1) {
        /* Handle error in digest update */ 
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Error updating digest.");
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        /* Handle error in digest finalization */ 
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Error finalizing digest.");
    }

    EVP_MD_CTX_free(ctx);

    string hashString;
    for (unsigned int i = 0; i < hashLen; ++i) {
        char hexChar[3];
        snprintf(hexChar, sizeof(hexChar), "%02x", hash[i]);
        hashString += hexChar;
    }

    return hashString;
}

/* This function is used to generate the session key from the shared key */
unsigned char* SHA256(const unsigned char* data, size_t dataSize)
{
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw runtime_error("Error creating EVP_MD_CTX.");
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Error initializing digest.");
    }

    if (EVP_DigestUpdate(ctx, data, dataSize) != 1) {
        EVP_MD_CTX_free(ctx);
        throw runtime_error("Error updating digest.");
    }

    unsigned char* hash = new unsigned char[EVP_MAX_MD_SIZE];
    unsigned int hashLen = 0;
    if (EVP_DigestFinal_ex(ctx, hash, &hashLen) != 1) {
        EVP_MD_CTX_free(ctx);
        delete[] hash;
        throw runtime_error("Error finalizing digest.");
    }

    EVP_MD_CTX_free(ctx);

    return hash;
}