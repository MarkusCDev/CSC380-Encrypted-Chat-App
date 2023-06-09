#include <stdio.h>
#include <string.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>


unsigned char* teacher;
unsigned char* mine;

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
void ctr_example(char* message, unsigned char* key, unsigned char* iv)
{
	//unsigned char key[32];
	size_t i;
	/* setup dummy (non-random) key and IV */
	//for (i = 0; i < 32; i++) key[i] = i;
	//unsigned char iv[16];
	//for (i = 0; i < 16; i++) iv[i] = i;
	/* NOTE: in general you need t compute the sizes of these
	 * buffers.  512 is an arbitrary value larger than what we
	 * will need for our short message. */
	unsigned char ct[512];
	unsigned char pt[512];
	/* so you can see which bytes were written: */
	memset(ct,0,512);
	memset(pt,0,512);
	//char* message = "123";
	//char* message = "this is a test message :D";
	//char* message = "9fce5be6212d926510269f97a2fd13cc1f1f2d6ed1c5241ac714b5d960d0d2c611277496f37e05c620d90a66e3daacea673e6efd85d2ae14afe9cfa0b65c8d64Hello";
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
	teacher = ct;
	printf("CIPHERERER: %s\n", ct);
	printf("Ctlen: %d\n", ctlen);
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
	printf("strlen: %d\n", strlen(pt));
	printf("sizeof: %d\n", sizeof(pt));
	/* NOTE: counter mode will preserve the length (although the person
	 * decrypting needs to know the IV) */
}


unsigned char* ctr_encrypt(char* message, unsigned char* key, unsigned char* iv){
    unsigned char* ct = (unsigned char*) malloc(512);
    memset(ct, 0, 512);
    size_t len = strlen(message);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, key, iv))
        ERR_print_errors_fp(stderr);
    int nWritten;
    if (1 != EVP_EncryptUpdate(ctx, ct, &nWritten, (unsigned char*) message, len))
        ERR_print_errors_fp(stderr);
    EVP_CIPHER_CTX_free(ctx);

    return ct;
}



unsigned char* ctr_decrypt(unsigned char* ct, unsigned char* key, unsigned char* iv, size_t length){
	
	unsigned char* pt = (unsigned char*) malloc(512);
	memset(pt, 0, 512);
	//size_t ctlen = strlen((const char*)ct);
	size_t ctlen = length;


	int nWritten;
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
		ERR_print_errors_fp(stderr);
	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctlen))
		ERR_print_errors_fp(stderr);
	
	
	return pt;
}



// unsigned char* ctr_encrypt(char* message, unsigned char* key, unsigned char* iv){
   
// 	printf("---ENCRYPT---\n");
// 	printf("Msg: %s\nKey: %s\nIV: %s\n", message, key, iv);
   
   
//    	unsigned char* ct = (unsigned char*) malloc(512*sizeof(unsigned char));
//     memset(ct, 0, 512);
//     size_t len = strlen(message);

//     EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
//     if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), 0, key, iv))
//         ERR_print_errors_fp(stderr);
//     int nWritten;
//     if (1 != EVP_EncryptUpdate(ctx, ct, &nWritten, (unsigned char*) message, len))
//         ERR_print_errors_fp(stderr);
//     EVP_CIPHER_CTX_free(ctx);

// 	//printf("Plain text: %s\nKey: %s\nIV: %s\nSize: %ld\n", ct, key, iv, strlen(ct));
// 	printf("ciphertext of length %i:\n",nWritten);
// 	for (size_t i = 0; i < 133; i++) {
// 		printf("%02x",ct[i]);
// 	}
// 	printf("\n");

// 	mine = ct;

//     return ct;
// }



// unsigned char* ctr_decrypt(unsigned char* ct, unsigned char* key, unsigned char* iv, size_t length){
	
// 	printf("---DECCRYPT---\n");
// 	printf("This is cipher text: %s\n", ct);
// 	printf("Key: %s\n", key);
// 	printf("IV: %s\n", iv);

// 	unsigned char* pt = (unsigned char*) malloc(512*sizeof(unsigned char));
// 	memset(pt, 0, 512);
// 	//size_t ctlen = strlen(ct);
// 	size_t ctlen = length;
// 	// size_t ctlen = 0;
// 	// for (size_t i = 0; i < 514; i++){
// 	// 	if (ct[i] != NULL){
// 	// 		ctlen ++;
// 	// 	}
// 	// }

// 	printf("Ctlen: %d\n", ctlen);
	
// 	int nWritten;
// 	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
// 	if (1!=EVP_DecryptInit_ex(ctx,EVP_aes_256_ctr(),0,key,iv))
// 		ERR_print_errors_fp(stderr);
// 	if (1!=EVP_DecryptUpdate(ctx,pt,&nWritten,ct,ctlen))
// 		ERR_print_errors_fp(stderr);
	
// 	printf("plain text: %s\n", pt);

	
// 	return pt;
// }

#include <stdbool.h>

bool compare_arrays(unsigned char* a, unsigned char* b, size_t length) {
    for (size_t i = 0; i < length; i++) {
        if (a[i] != b[i]) {
			printf("I: %d,a %d,b %d", i, a[i], b[i]);
            return false;
        }
    }
    return true;
}



/* TODO: add signature example  */

int main()
{

	unsigned char* keynew = "217e497cd8ee21a69216b4da362cee5c3df6913768086570fb08ba133ca090dd29f7097b5cb79f5e81189b2389403da52e62a892623e39477e34869dded94292dad3ff3e68a7bb751f1af80967947109a4807c0c011cd1456241b0832fde568872a7a1927412df310212a0e91ec1f3fecdb282ceae45d6a057211986912c85b3";
	//unsigned char* ivnew = "ioxc5ox92oxa6ox03oxdeoxb7oxbbpoxd5ox1foxabtxoxd6oxbe";
	unsigned char* iv = "1234567890123456";
	char* msg = "047434c18585569b723333dac43af200752972678c31b3631c9e1b56992bb5cd1265c1031210414eeb3a54b262cd4d942c783f067fc67b0d622337238d95d45ahellos";
	//char* msg = "9fce5be6212d926510269f97a2fd13cc1f1f2d6ed1c5241ac714b5d960d0d2c611277496f37e05c620d90a66e3daacea673e6efd85d2ae14afe9cfa0b65c8d64Hello";
	//char* msg = "hellos";
	//char* msg = "36a680b54952e8e6abf5906b25fe049a340222ad4f573382560cce3aba26475ab320ef204e862f8d36d891a6eae29edbbbf5aa067e9033d51014d090247d2d78hellos";
	//char* msg = "540d761883e18f8217e6aa1edb733e0633b4616286d6b5ca81f922612d8d81ebc9893161595fa9a96c696b93bb8cb0720c1676978f232e99f7e6c1f2024875ddhello";
	// rsa_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	ctr_example(msg,keynew, iv);
	printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// sha_example();
	// printf("~~~~~~~~~~~~~~~~~~~~~~~\n");
	// hmac_example();
	printf("~~~~~~~~TESTING~~~~~~~~~\n");
	printf(msg);
	printf("\n");
	printf("strlen: %ld\n", strlen(msg));
	printf("sizeof: %ld\n", sizeof(msg));



	// unsigned char key[32];
	// size_t i;
	// for (i = 0; i < 32; i++) key[i] = i;
	// unsigned char iv[16];
	// for (i = 0; i < 16; i++) iv[i] = i;





    //Encryption
	printf("Test\n");
    unsigned char* ct = ctr_encrypt(msg,keynew, iv);
	printf("Test0\n");
	 	for (size_t i = 0; i < strlen(msg); i++) {
	 	printf("%02x",ct[i]);
	 }
	printf("\n");
	printf("strlen: %ld\n", strlen(ct));
	printf("sizeof: %ld\n", sizeof(ct));

	printf("Test1\n");


	//Decryption
	printf("Test2\n");
    unsigned char* decrypted = ctr_decrypt(ct, keynew, iv, strlen(msg));
	printf("Test3\n");

    //Print decrypted plaintext
    printf("Decrypted plaintext:\n");
    printf("%s\n", decrypted);
	// if (compare_arrays(teacher, mine, strlen(msg))) {
    // printf("The arrays are equal.\n");
    //  } else {
    // printf("The arrays are not equal.\n");
    //  }        




	return 0;
}