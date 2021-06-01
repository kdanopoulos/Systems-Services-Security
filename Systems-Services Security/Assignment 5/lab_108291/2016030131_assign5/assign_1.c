#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/cmac.h>

#define BLOCK_SIZE 16
#define AES_ECB(bits) (bits == 128) ? EVP_aes_128_ecb() : EVP_aes_256_ecb()


/* function prototypes */
void print_hex(unsigned char *, size_t);
void print_string(unsigned char *, size_t); 
void usage(void);
void check_args(char *, char *, unsigned char *, int, int);
void keygen(unsigned char *, unsigned char *, unsigned char *, int);
void encrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int );
int decrypt(unsigned char *, int, unsigned char *, unsigned char *, 
    unsigned char *, int);
void gen_cmac(unsigned char *, size_t, unsigned char *, unsigned char *, int);
int verify_cmac(unsigned char *, unsigned char *);



/* TODO Declare your function prototypes here... */
unsigned char *readFile(char *);
char *inputString(FILE* , size_t );
char *findCMAC(FILE* , size_t );
void encryptAndStore(char *,char *,unsigned char *, unsigned char *,int );
void decryptAndStore(char *,char *,unsigned char *, unsigned char *,int );
void encryptAndStoreWithCMAC(char *,char *,unsigned char *, unsigned char *,int );
int decryptVerifyAndStore(char *,char *,unsigned char *, unsigned char *,int );



/*
 * Prints the hex value of the input
 * 16 values per line
 */
void
print_hex(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++) {
			if (!(i % 16) && (i != 0))
				printf("\n");
			printf("%02X ", data[i]);
		}
		printf("\n");
	}
}


/*
 * Prints the input as string
 */
void
print_string(unsigned char *data, size_t len)
{
	size_t i;

	if (!data)
		printf("NULL data\n");
	else {
		for (i = 0; i < len; i++)
			printf("%c", data[i]);
		printf("\n");
	}
}


/*
 * Prints the usage message
 * Describe the usage of the new arguments you introduce
 */
void
usage(void)
{
	printf(
	    "\n"
	    "Usage:\n"
	    "    assign_1 -i in_file -o out_file -p passwd -b bits" 
	        " [-d | -e | -s | -v]\n"
	    "    assign_1 -h\n"
	);
	printf(
	    "\n"
	    "Options:\n"
	    " -i    path    Path to input file\n"
	    " -o    path    Path to output file\n"
	    " -p    psswd   Password for key generation\n"
	    " -b    bits    Bit mode (128 or 256 only)\n"
	    " -d            Decrypt input and store results to output\n"
	    " -e            Encrypt input and store results to output\n"
	    " -s            Encrypt+sign input and store results to output\n"
	    " -v            Decrypt+verify input and store results to output\n"
	    " -h            This help message\n"
	);
	exit(EXIT_FAILURE);
}


/*
 * Checks the validity of the arguments
 * Check the new arguments you introduce
 */
void
check_args(char *input_file, char *output_file, unsigned char *password, 
    int bit_mode, int op_mode)
{
	if (!input_file) {
		printf("Error: No input file!\n");
		usage();
	}

	if (!output_file) {
		printf("Error: No output file!\n");
		usage();
	}

	if (!password) {
		printf("Error: No user key!\n");
		usage();
	}

	if ((bit_mode != 128) && (bit_mode != 256)) {
		printf("Error: Bit Mode <%d> is invalid!\n", bit_mode);
		usage();
	}

	if (op_mode == -1) {
		printf("Error: No mode\n");
		usage();
	}
}


/*
 * Generates a key using a password
 */
void
keygen(unsigned char *password, unsigned char *key, unsigned char *iv, int bit_mode)
{

	/* TODO Task A */
    //initialization
    /*
	EVP_MD_CTX * evpCtx = EVP_MD_CTX_new ();
    EVP_DigestInit_ex (evpCtx, EVP_sha1(), NULL);
	// hash calculation
    EVP_DigestUpdate (evpCtx, password, strlen(password));
    unsigned char result [bit_mode] = {0};
	// Return result
    EVP_DigestFinal_ex (evpCtx, result, & len);
    key = &result;*/
    EVP_BytesToKey(AES_ECB(bit_mode), EVP_sha1(), NULL, password,strlen((const char *) password), 1, key, iv);
}


/*
 * Encrypts the data
 */
void
encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext, int bit_mode)
{

	/* TODO Task B */
	EVP_CIPHER_CTX *ctx;
    int curlen;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())){
        ERR_print_errors_fp(stderr);
        abort();
    }

    /*
     * Initialise the encryption operation with the appropriate mode 
     */
    if(1 != EVP_EncryptInit_ex(ctx, AES_ECB(bit_mode), NULL, key, iv)){
        ERR_print_errors_fp(stderr);
        abort();
    }
    // encryption
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &curlen, plaintext, plaintext_len)){
        ERR_print_errors_fp(stderr);
        abort();
    }
    ciphertext_len = curlen;
    // Finalise encryption
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + curlen, &curlen)){
        ERR_print_errors_fp(stderr);
        abort();
    }
    ciphertext_len += curlen;

    EVP_CIPHER_CTX_free(ctx);
}


/*
 * Decrypts the data and returns the plaintext size
 */
/*int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext, int bit_mode)
{
	printf("Inside\n");
	int plaintext_len;

	plaintext_len = 0;

	//TODO Task C 
	EVP_CIPHER_CTX *ctx;
	int templen;
	//Create and initialise the context 
    if(!(ctx = EVP_CIPHER_CTX_new())){
        ERR_print_errors_fp(stderr);
        abort();
    }
     
      //Initialise the dencryption operation with the appropriate mode 
     
    if(1 != EVP_DecryptInit_ex(ctx, AES_ECB(bit_mode), NULL, key, iv)){
        ERR_print_errors_fp(stderr);
        abort();
    }
     printf("initialization done\n");
    // decryption
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &templen, ciphertext, ciphertext_len)){
    	printf("koukou\n");
        ERR_print_errors_fp(stderr);
        abort();
    }
    printf("update\n");
    plaintext_len = templen;
    // Finalise decryption
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + templen, &templen)){
        ERR_print_errors_fp(stderr);
        abort();
    }
    printf("Finalise\n");
    plaintext_len += templen;

    EVP_CIPHER_CTX_free(ctx);


	return plaintext_len;
}*/
int
decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
		unsigned char *iv, unsigned char *plaintext, int bit_mode) {


	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	int plaintext_len, len;
	plaintext_len = 0;

	EVP_DecryptInit_ex(ctx, AES_ECB(bit_mode), NULL, key, NULL);
	EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
	plaintext_len = len;
	EVP_DecryptFinal_ex(ctx, ciphertext + len, &len);
	plaintext_len += len;
	//EVP_CIPHER_CTX_free(ctx);
	return plaintext_len;
}


/*
 * Generates a CMAC
 */
void
gen_cmac(unsigned char *data, size_t data_len, unsigned char *key, 
    unsigned char *cmac, int bit_mode)
{

	/* TODO Task D */
    size_t cmaclen;
    CMAC_CTX *ctx = CMAC_CTX_new();
    CMAC_Init(ctx, key, bit_mode / 8, AES_ECB(bit_mode), NULL);
    CMAC_Update(ctx, data, data_len);
    CMAC_Final(ctx, cmac, &cmaclen);
    CMAC_CTX_free(ctx);
}


/*
 * Verifies a CMAC
 */
int verify_cmac(unsigned char *cmac1, unsigned char *cmac2)
{

	for(int i=0;i<BLOCK_SIZE;i++){
		if(cmac1[i]!=cmac2[i])
			return 0;
	}

	return 1;
}



/* TODO Develop your functions here... */

unsigned char *read_file(FILE *fp,unsigned long *data_len) {
	unsigned char *data;
	fseek (fp, 0, SEEK_END);
	*data_len = ftell(fp);
	fseek (fp, 0, SEEK_SET);
	data = malloc(*data_len);
	fread(data, 1, *data_len, fp);
	return data;
}

unsigned char *readcontent(FILE *fp)
{
    char *fcontent = NULL;
    int fsize = 0;
    if(fp) {
        fseek(fp, 0, SEEK_END);
        fsize = ftell(fp);
        rewind(fp);

        fcontent = (char*) malloc(sizeof(char) * fsize);
        fread(fcontent, 1, fsize, fp);

    }
    return fcontent;
}

char *inputString(FILE* fp, size_t size){
//The size is extended by the input with the value of the provisional
    char *str;
    int ch;
    size_t len = 0;
    str = realloc(NULL, sizeof(char)*size);//size is start size
    if(!str)return str;
    while(1){
    	if(!(EOF!=(ch=fgetc(fp)) )){
    			break;
    	}
        str[len++]=ch;
        if(len==size){
            str = realloc(str, sizeof(char)*(size+=16));
            if(!str)return str;
        }
    }
    str[len++]='\0';

    return realloc(str, sizeof(char)*len);
}

char *findText(FILE* fp, int size){
	printf("Inside function\n");
    char *str;
    int ch;
    int len = 0;
    int endFoound=0;
    int line = 0;
    int l = 0;
    str = realloc(NULL, sizeof(char)*size);//size is start size
    if(!str)return str;
    while(1){
    	if(endFoound==1){
    		len-=3;
    		break;
    	}
    	if((EOF==(ch=fgetc(fp)) ) ){
    			return NULL;
    	}
    	if(line==0){ // line = 0
				if(ch=='\n')
					line=1;
			}else{ // line = 1 
				if(l==0){ // l = 0
					if(ch=='|')
						l=1;
					else if(ch!='\n')
						line=0;
				}else{ // l =1
					if(ch=='k')
						endFoound=1;
					else if(ch=='\n')
						l=0;
					else{
						line=0;
						l=0;
					}
				}
			}
        str[len++]=ch;
        if(len==size){
            str = realloc(str, sizeof(char)*(size+=16));
            if(!str)return str;
        }
    }
    str[len++]='\0';

    return realloc(str, sizeof(char)*len);
}

char *findCMAC(FILE* fp, size_t size){
//The size is extended by the input with the value of the provisional
    char *str;
    int ch;
    size_t len = 0;
    int cmacFound = 0;
    int line = 0;
    int l = 0;
    str = realloc(NULL, sizeof(char)*size);//size is start size
    if(!str)return str;
    while(1){
    	if(!(EOF!=(ch=fgetc(fp)) )){
    		if(cmacFound=0)
    			return NULL;
    		break;
    	}
    	if(cmacFound = 0){
    		if(line==0){ // line = 0
				if(ch=='\n')
					line=1;
				continue;
			}else{ // line = 1 
				if(l==0){ // l = 0
					if(ch=='|')
						l=1;
					else if(ch!='\n')
						line=0;
					continue;
				}else{ // l =1
					if(ch=='k')
						cmacFound=1;
					else if(ch=='\n')
						l=0;
					else{
						line=0;
						l=0;
					}
					continue;
				}
			}
    	}
        str[len++]=ch;
        if(len==size){
            str = realloc(str, sizeof(char)*(size+=16));
            if(!str)return str;
        }
    }
    str[len++]='\0';

    return realloc(str, sizeof(char)*len);
}


/*
 * Encrypts the input file and stores the ciphertext to the output file
*/
void encryptAndStore(char *input_file,char *output_file,unsigned char *key, unsigned char *iv,int bit_mode){
	char *plaintext;
	unsigned long plainLen;
	FILE *fp;
	fp = fopen(input_file, "rb");
	plaintext = read_file(fp,&plainLen);
	fclose(fp);

	// the input file is taken from the inputfile and stored to variable plaintext
	unsigned long cipherLen = plainLen - (plainLen % BLOCK_SIZE) + BLOCK_SIZE;
	unsigned char *ciphertext = malloc(cipherLen);
	encrypt(plaintext, strlen(plaintext), key,iv, ciphertext, bit_mode);

	fp = fopen(output_file,"wb");
	fwrite(ciphertext, 1, cipherLen, fp);
	fclose(fp);
	free(ciphertext);
}
 /*
 *
 * Decrypts the input file and stores the plaintext to the output file
 */
void decryptAndStore(char *input_file,char *output_file,unsigned char *key, unsigned char *iv,int bit_mode){
	char *ciphertext;
	unsigned long cipherLen;
	FILE *fp;
	fp = fopen(input_file,"rb");
	if( fp == NULL ) {
    	fprintf(stderr, "Couldn't open %s: %s\n", input_file, strerror(errno));
    	exit(1);
	}
	ciphertext = read_file(fp,&cipherLen);
	fclose(fp);
	unsigned char *plaintext;
	unsigned long plaintextLen;
	plaintext = malloc(cipherLen);
	plaintextLen = decrypt(ciphertext, strlen(ciphertext), key,iv, plaintext, bit_mode);
	fp = fopen(output_file,"wb");
	fwrite(plaintext, 1, plaintextLen, fp);
	fclose(fp);
	free(plaintext);

}
 /* Encrypts and signs the input file and stores the ciphertext concatenated with 
 * the CMAC to the output file
 */
void encryptAndStoreWithCMAC(char *input_file,char *output_file,unsigned char *key, unsigned char *iv,int bit_mode){
	char *plaintext;
	unsigned long plainLen;
	FILE *fp;
	fp = fopen(input_file, "rb");
	plaintext = read_file(fp,&plainLen);
	fclose(fp);

	// the input file is taken from the inputfile and stored to variable plaintext
	unsigned long cipherLen = plainLen - (plainLen % BLOCK_SIZE) + (2 * BLOCK_SIZE);
	unsigned char *ciphertext = malloc(cipherLen);
	encrypt(plaintext, plainLen, key,iv, ciphertext, bit_mode);
	gen_cmac(plaintext, plainLen, key, ciphertext + (cipherLen - BLOCK_SIZE), bit_mode);

	fp = fopen(output_file,"wb");
	fwrite(ciphertext, 1, cipherLen, fp);
	//fputs( "\n|k", fp );
	//fputs( cmac, fp );
	fclose(fp);
	free(ciphertext);
}
 /* Decrypts and verifies the input file and stores the plaintext to the output
 * file
 */
int decryptVerifyAndStore(char *input_file,char *output_file,unsigned char *key, unsigned char *iv,int bit_mode){
	char *ciphertext;
	unsigned long clen;
	//char *cmacObtained;
	FILE *fp;
	fp = fopen(input_file,"rb");
	//----------------------
	//printf("%s\n", inputString(fp,10) );
	ciphertext = read_file(fp, &clen);
	//ciphertext = readcontent(fp); // we read all data from file 
	//if(ciphertext==NULL){
	//	printf("No cmac found\n");
	//	return -1;
	//}
	//cmacObtained = readFrom(fp,strlen(ciphertext)- BLOCK_SIZE);
	//cmacObtained = findCMAC(fp,10);
	//----------------------
	fclose(fp);

	int temp1,temp2;
	temp1 = (int)clen;
	temp2 = (int)BLOCK_SIZE;
	unsigned char *plaintext;
	unsigned long plaintextLen;
	plaintext = malloc(temp1-temp2);
	plaintextLen = decrypt(ciphertext, temp1-temp2, key,iv, plaintext, bit_mode);
	char newCmac[BLOCK_SIZE];
	gen_cmac(plaintext, plaintextLen, key, newCmac, bit_mode);

	if(verify_cmac(newCmac,ciphertext + (strlen(ciphertext) - BLOCK_SIZE))){
		// the cmac 's are same
		printf("Have the same key\n");
		fp = fopen(output_file,"wb");
		fwrite(plaintext, 1, plaintextLen, fp);
		fclose(fp);
		free(plaintext);
		return 1;
	}
	free(plaintext);
	printf("Don't have the same key\n");
	return 0;
}

int
main(int argc, char **argv)
{
	int opt;			/* used for command line arguments */
	int bit_mode;			/* defines the key-size 128 or 256 */
	int op_mode;			/* operation mode */
	char *input_file;		/* path to the input file */
	char *output_file;		/* path to the output file */
	unsigned char *password;	/* the user defined password */

	/* Init arguments */
	input_file = NULL;
	output_file = NULL;
	password = NULL;
	bit_mode = -1;
	op_mode = -1;


	/*
	 * Get arguments
	 */
	while ((opt = getopt(argc, argv, "b:i:m:o:p:desvh:")) != -1) {
		switch (opt) {
		case 'b':
			bit_mode = atoi(optarg);
			break;
		case 'i':
			input_file = strdup(optarg);
			break;
		case 'o':
			output_file = strdup(optarg);
			break;
		case 'p':
			password = (unsigned char *)strdup(optarg);
			break;
		case 'd':
			/* if op_mode == 1 the tool decrypts */
			op_mode = 1;
			break;
		case 'e':
			/* if op_mode == 1 the tool encrypts */
			op_mode = 0;
			break;
		case 's':
			/* if op_mode == 1 the tool signs */
			op_mode = 2;
			break;
		case 'v':
			/* if op_mode == 1 the tool verifies */
			op_mode = 3;
			break;
		case 'h':
		default:
			usage();
		}
	}


	/* check arguments */
	check_args(input_file, output_file, password, bit_mode, op_mode);

	unsigned char key[256];//, iv[256];
	unsigned char *iv = NULL;



	/* TODO Develop the logic of your tool here... */




	/* Initialize the library */


	/* Keygen from password */
	keygen(password, key, iv, bit_mode);


	/* Operate on the data according to the mode */
	switch (op_mode) {
		case 0:
			/* encrypt */
			encryptAndStore(input_file,output_file,key, iv,bit_mode);
			break;

		case 1:
			/* decrypt */
			decryptAndStore(input_file,output_file,key, iv,bit_mode);
			break;

		case 2:
			/* sign */
			encryptAndStoreWithCMAC(input_file,output_file,key, iv,bit_mode);
			break;

		case 3:
			/* verify */
			return decryptVerifyAndStore(input_file,output_file,key, iv,bit_mode);
			break;

		default:
			break;
	}
		

	/* Clean up */
	free(input_file);
	free(output_file);
	free(password);


	/* END */
	return 0;
}
