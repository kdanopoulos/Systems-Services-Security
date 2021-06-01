#ifndef SIMPLE_CRYPTO_H
#define SIMPLE_CRYPTO_H


struct minMax{
	int min;
	int max;
};



//-------------------------------------------------------------
void oneTimePadEncrypt(char * input,char * key,char * ptr);
void oneTimePadDecrypt(char * input,char * key,char *ptr);
//-------------------------------------------------------------


//-------------------------------------------------------------
void caesarCipherEncrypt(char * input,int key,char *ptr);
void caesarCipherDecrypt(char * input,int key,char *ptr);
//-------------------------------------------------------------


//-------------------------------------------------------------
void vigenereCipherEncrypt(char * input,char * key,char *ptr);
void vigenereCipherDecrypt(char * input,char * key,char *ptr);
//-------------------------------------------------------------



//--------------- Help Functions -------------------



struct minMax findMinMax(char *input);

void printEncryptedKey(int mySize,char * input,int a,int b);

void getRandomKey(int length,char *ptr);

char *inputString(FILE* fp, size_t size);

void demoOTP();

void demoCC();

void demoVC();

#endif