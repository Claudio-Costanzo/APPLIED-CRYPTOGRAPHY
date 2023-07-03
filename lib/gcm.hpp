#include<openssl/evp.h>
#include<fstream>

using namespace std;

/* Utility function for error managing */
int reportErrors()
{
	printf("An error occourred.\n");
	exit(1);
}

int gcm_encrypt(unsigned char *plaintext, int plaintext_len,
                unsigned char *aad, int aad_len,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *ciphertext,
                unsigned char *tag)
{
    EVP_CIPHER_CTX *ctx;
    int ciphertext_len=0;
    int len=0;
    
    /* Create and initialise the context */ 
    if(!(ctx = EVP_CIPHER_CTX_new()))
        reportErrors();

    /* Initialise the encryption operation */ 
    if(1 != EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        reportErrors();

    /* Provide any AAD data. This can be called zero or more times as required */
    if(1 != EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len))
        reportErrors();

    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        reportErrors();

    ciphertext_len = len;

	/* Finalize Encryption */
    if(1 != EVP_EncryptFinal(ctx, ciphertext + len, &len))
        reportErrors();

    ciphertext_len += len;

    /* Get the tag */
    if(1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag))
        reportErrors(); 

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int gcm_decrypt(unsigned char *ciphertext, int ciphertext_len,
                unsigned char *aad, int aad_len,
                unsigned char *tag,
                unsigned char *key,
                unsigned char *iv, int iv_len,
                unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int plaintext_len;
    int len;
    int ret;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new()))
        reportErrors();

    if(!EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv))
        reportErrors();

	/* Provide any AAD data */
    if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
        reportErrors();

	/* Provide the message to be decrypted, and obtain the plaintext output */
    if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        reportErrors();

    plaintext_len = len;

    /* Set expected tag value. Works in OpenSSL 1.0.1d and later */
    if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag))
        reportErrors();

    /*
     * Finalise the decryption. A positive return value indicates success,
     * anything else is a failure - the plaintext is not trustworthy.
     */
    ret = EVP_DecryptFinal(ctx, plaintext + len, &len);

    /* Clean up */
    EVP_CIPHER_CTX_cleanup(ctx);

    if(ret > 0) {
        /* Success */
        plaintext_len += len;
        return plaintext_len;
    } else {
        /* Verify failed */
        return -1;
    }
}