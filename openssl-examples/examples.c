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
	char* message = "this is a test message.";
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
	//printf("actual int: %u \n", ct);
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


unsigned char* encrypt(char* message, unsigned char* key, unsigned char* iv)
{
    unsigned char* ct = malloc(sizeof(unsigned char)*512);
	int nWritten;
    size_t len = strlen(message);
	
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1!=EVP_EncryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
        ERR_print_errors_fp(stderr);

    if (1!=EVP_EncryptUpdate(ctx,ct,&nWritten,(unsigned char*)message,len))
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);

	return ct;
}


char* decrypt(unsigned char* ct, unsigned char* key, unsigned char* iv)
{
    char* pt = malloc(sizeof(char)*512);
	int nWritten;
	size_t ctlen = strlen(ct);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
        ERR_print_errors_fp(stderr);
    
    if (1!=EVP_DecryptUpdate(ctx,(unsigned char*)pt,&nWritten,ct,ctlen))
        ERR_print_errors_fp(stderr);

    EVP_CIPHER_CTX_free(ctx);
    
	return pt;
	
}


int main()
{
	// rsa_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	ctr_example();
	//printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// sha_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// hmac_example();
	printf("~~~~~~~~TESTING~~~~~~~~~\n");

	//message
	char* message = "this is a test message.";
	// //key
	unsigned char key[32];
	 	for (size_t i = 0; i < 32; i++) key[i] = i;
	 //iv
	 unsigned char iv[16];
	 	for (size_t i = 0; i < 16; i++) iv[i] = i;

	
	unsigned char* ct = encrypt(message, key, iv);
	char* pt = decrypt(ct, key, iv);

	printf("Original message: %s\n", message);
	printf("Ciphertext: ");
	for (size_t i = 0; i < strlen(ct); i++) {
    	printf("%02x", ct[i]);
	}
	printf("\nDecrypted message: %s\n", pt);


	return 0;
}
