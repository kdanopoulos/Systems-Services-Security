#include "rsa.h"
#include "utils.h"

/*
 * Sieve of Eratosthenes Algorithm
 * https://en.wikipedia.org/wiki/Sieve_of_Eratosthenes
 *
 * arg0: A limit
 * arg1: The size of the generated primes list. Empty argument used as ret val
 *
 * ret:  The prime numbers that are less or equal to the limit
 */
size_t *sieve_of_eratosthenes(int limit, int *primes_sz){
	size_t prime[limit+1];
	*primes_sz = limit-1;
	/* TODO */	
	//memset(prime,'y',(limit+1)*sizeof(size_t) );
	for(int i=0;i<limit+1;i++){
		prime[i] = 1;
	}
	for(int p=2;p*p<=limit;p++){
		if(prime[p]){
			for(int i=p*p;i<=limit;i+=p){
				if(prime[i]==1){
					prime[i] = 0;
					*primes_sz=*primes_sz-1;
				}
			}
		}
	}
	size_t *list = malloc((*primes_sz)*sizeof(size_t));
	int i=0;
    for(int p=2;p<=limit;p++){
    	if(prime[p]){
    		list[i]=p;
    		i++;
    	}
    }	
    return list;
}


/*
 * Greatest Common Denominator
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: the GCD
 */
int
gcd(int a, int b)
{
	/* TODO */
	int r;
	while(b!=0){
		r = a%b;
		a = b;
		b = r;
	}
	return a;
}


/*
 * Chooses 'e' where 
 *     1 < e < fi(n) AND gcd(e, fi(n)) == 1
 *
 * arg0: fi(n)
 *
 * ret: 'e'
 */
size_t
choose_e(size_t fi_n)
{
	size_t e;
	size_t * list;
	size_t len;
	list = sieve_of_eratosthenes(RSA_SIEVE_LIMIT,&len);
	/* TODO */
	for(int i=0;i<len;i++){
		e = list[i];
		if( (e%fi_n!=0) && (gcd(e,fi_n)==1) ){
			return e;
		}
	}
	free(list);
	return NULL;
}

size_t *readRSAKey(char * input_file){
	FILE *fp;
	fp = fopen(input_file, "rb");
	size_t key[2];
	size_t count = fread(&key, sizeof(size_t), 10, fp);
	if(count!=2){
		printf("Error Unkown key layout\n");
		fclose(fp);
		return NULL;
	}
	fclose(fp);
	size_t *listKey;
	listKey = malloc(2*sizeof(size_t));
	listKey[0] = key[0];
	listKey[1] = key[1];
	return listKey;
}
unsigned char *read_file(FILE *fp,unsigned long *data_len){
	unsigned char *data;
	fseek (fp, 0, SEEK_END);
	*data_len = ftell(fp);
	fseek (fp, 0, SEEK_SET);
	data = malloc(*data_len);
	fread(data, 1, *data_len, fp);
	return data;
}

size_t *read_file2(FILE *fp,unsigned long *data_len){
	size_t text[100000];
	*data_len = fread(text,sizeof(size_t),100000,fp);
	size_t *data;
	data = malloc(*data_len*sizeof(size_t));
	for(int i=0;i<*data_len;i++){
		data[i]=text[i];
	}
	return data;
}


/*
 * Calculates the modular inverse
 *
 * arg0: first number
 * arg1: second number
 *
 * ret: modular inverse
 */
size_t
mod_inverse(size_t a, size_t b)
{
	/* TODO */
	a = a % b;
    for (int x = 1; x < b; x++)
        if ((a * x) % b == 1)
            return x;

}

size_t computeMod(size_t b , size_t e , size_t mod){
	size_t result =1;
	for(int i=1;i<=e;i++){
		result = (result*b) % mod;
	}
	return result;
}


/*
 * Generates an RSA key pair and saves
 * each key in a different file
 */
void rsa_keygen(){
	size_t p;
	size_t q;
	size_t n;
	size_t fi_n;
	size_t e;
	size_t d;

	/* TODO */

	srand(time(NULL));
	size_t * list;
	size_t len;
	list = sieve_of_eratosthenes(RSA_SIEVE_LIMIT,&len);
	int num ;
	int range = len;
	int min = 0;
	int random_number;
	random_number = rand() % range + min;
	num = random_number;
	p = list[num];
	random_number = rand() % range + min;
	num = random_number;
	q = list[num];
	n = p * q;
	fi_n = (p-1)*(q-1);
	e = choose_e(fi_n);
	d = mod_inverse(e, fi_n);


	FILE *fp;
	fp = fopen("public.key","wb");
	fwrite(&n, 1, sizeof(size_t), fp);
	fwrite(&d, 1, sizeof(size_t), fp);
	fclose(fp);

	fp = fopen("private.key","wb");
	fwrite(&n, 1, sizeof(size_t), fp);
	fwrite(&e, 1, sizeof(size_t), fp);
	fclose(fp);
	free(list);

}


/*
 * Encrypts an input file and dumps the ciphertext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_encrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */
	// read the key from the file
	size_t *key;
	key = readRSAKey(key_file);
	// read the plaintext from the file
	char *plaintext;
	unsigned long plainLen;
	FILE *fp;
	fp = fopen(input_file, "rb");
	plaintext = read_file(fp,&plainLen);
	fclose(fp);

	size_t msg;
	size_t cyphertext[plainLen];
	for(int i=0;i<plainLen;i++){
		msg = plaintext[i];
		if(msg>=key[0]){
			printf("Error\n");
			break;
		}
		cyphertext[i] = computeMod(msg,key[1],key[0]);
	}

	fp = fopen(output_file,"wb");
	fwrite(cyphertext, plainLen, sizeof(size_t), fp);
	fclose(fp);
	free(plaintext);
	free(key);
}


/*
 * Decrypts an input file and dumps the plaintext into an output file
 *
 * arg0: path to input file
 * arg1: path to output file
 * arg2: path to key file
 */
void
rsa_decrypt(char *input_file, char *output_file, char *key_file)
{

	/* TODO */
	// read the key from the file
	size_t *key;
	key = readRSAKey(key_file);
	// read the cyphertext from the file
	size_t *cyphertext;
	unsigned long cypherLen;
	FILE *fp;
	fp = fopen(input_file, "rb");
	cyphertext = read_file2(fp,&cypherLen);
	fclose(fp);

	size_t msg;
	char plaintext[cypherLen];
	for(int i=0;i<cypherLen;i++){
		msg = cyphertext[i];
		if(msg>=key[0]){
			printf("Error\n");
			break;
		}
		plaintext[i] = computeMod(msg,key[1],key[0]);
	}

	fp = fopen(output_file,"wb");
	fwrite(plaintext, cypherLen, sizeof(char), fp);
	fclose(fp);
	free(cyphertext);
	free(key);
}
