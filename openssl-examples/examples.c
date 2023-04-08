/* examples of using various crypto utilities from openssl. */
#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>




/* demonstrates hashing (SHA family) */
void sha_example()
{
	/* hash a string with sha256 */
	char* message = "this is a test message :D";
	unsigned char hash[32]; /* change 32 to 64 if you use sha512 */
	SHA256((unsigned char*)message,strlen(message),hash);
	for (size_t i = 0; i < 32; i++) {
		printf("%02x",hash[i]);
	}
	printf("\n");
	/* you can check that this is correct by running
	 * $ echo -n 'this is a test message :D' | sha256sum */
}

/* demonstrates HMAC */
void hmac_example()
{
	char* hmackey = "asdfasdfasdfasdfasdfasdf";
	unsigned char mac[64]; /* if using sha512 */
	memset(mac,0,64);
	char* message = "this is a test message :D";
	HMAC(EVP_sha512(),hmackey,strlen(hmackey),(unsigned char*)message,
			strlen(message),mac,0);
	printf("hmac-512(\"%s\"):\n",message);
	for (size_t i = 0; i < 64; i++) {
		printf("%02x",mac[i]);
	}
	printf("\n");
}

/* demonstrates AES in counter mode */
void ctr_example()
{
	unsigned char key[32];
	size_t i;
	/* setup dummy (non-random) key and IV */
	for (i = 0; i < 32; i++) key[i] = i;
	unsigned char iv[16];
	for (i = 0; i < 16; i++) iv[i] = i;
	/* NOTE: in general you need t compute the sizes of these
	 * buffers.  512 is an arbitrary value larger than what we
	 * will need for our short message. */
	unsigned char ct[512];
	unsigned char pt[512];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,512);
	char* message = "this is a test message :D";
	size_t len = strlen(message);
	/* encrypt: */
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	int nWritten; /* stores number of written bytes (size of ciphertext) */
	if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message,len))
		ERR_print_errors_fp(stderr);
	EVP_CIPHER_CTX_free(ctx);
	size_t ctlen = nWritten;
	printf("ciphertext of length %i:\n",nWritten);
	for (i = 0; i < ctlen; i++) {
		printf("%02x",ct[i]);
	}
	printf("\n");
	/* now decrypt.  NOTE: in counter mode, encryption and decryption are
	 * actually identical, so doing the above again would work.  Also
	 * note that it is crucial to make sure IVs are not reused, though it
	 * Won't be an issue for our hybrid scheme as AES keys are only used
	 * once.  */
	/* wipe out plaintext to be sure it worked: */
	memset(pt,0,512);
	ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctlen))
		ERR_print_errors_fp(stderr);
	printf("decrypted %i bytes:\n%s\n",nWritten,pt);
	/* NOTE: counter mode will preserve the length (although the person
	 * decrypting needs to know the IV) */
}



size_t ctlen;
int nWritten;

char* ctr_encrypt(char* msg)
{
	unsigned char key[32];
	size_t i;
	/* setup dummy (non-random) key and IV */
	for (i = 0; i < 32; i++) key[i] = i;
	unsigned char iv[16];
	for (i = 0; i < 16; i++) iv[i] = i;

    unsigned char ct[512];
    // so you can see which bytes were written: 
    memset(ct,0,512);
    size_t len = strlen(msg);
    // encrypt: 

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
        ERR_print_errors_fp(stderr);
    nWritten; // stores number of written bytes (size of ciphertext) 
    if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)msg,len))
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);
    ctlen = nWritten; // maybe change
    char cipher[512];
    for (size_t i = 0; i < ctlen; i++) {
        sprintf(&cipher[i*2],"%02x",ct[i]);
    }
    return strdup(cipher);
}


char* ctr_decrypt(char** ct) 
{
	unsigned char pt[512];
	unsigned char key[32];
	size_t i;
	/* setup dummy (non-random) key and IV */
	for (i = 0; i < 32; i++) key[i] = i;
	unsigned char iv[16];
	for (i = 0; i < 16; i++) iv[i] = i;

	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	memset(pt,0,512);
	ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctlen))
		ERR_print_errors_fp(stderr);

	return strdup(pt);

}









/* TODO: add signature example  */

int main()
{
	// rsa_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	ctr_example();
	printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// sha_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// hmac_example();
	printf("~~~~~~~~TESTING~~~~~~~~~\n");
	char* msg = "this is a test message :D";
	printf(msg);
	printf("\n");
	
	char* ct = ctr_encrypt(msg);
	printf("bytes:\n%s\n", ct);

	char* pt = ctr_decrypt(&ct);
	printf("secret:\n%s\n", pt);

	// char* dec = decrypt(enc);
	// printf(dec);



	return 0;
}
