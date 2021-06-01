#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include"simple_crypto.h"

//-------------------------------------------------------------
void oneTimePadEncrypt(char * input,char * key,char * ptr){
	int size = strlen(input);
	int invalidInput=0;
	char output[size];
	for(int i=0;i<size;i++){
		if(input[i]<48 || input[i]>122 ){
			invalidInput = 1;
			break;
		}
		output[i] = input[i] ^ key[i];
	}
	if(invalidInput==0){
		printf("[OTP] input: ");
		for(int i=0;i<size;i++){
			printf("%c",input[i]);
		}
		printf("\n");
	    strcpy(ptr,output);
	}else{
		printf("Error\nThe input is invalid\n");
		ptr = NULL;
	}
}
void oneTimePadDecrypt(char * input,char * key,char *ptr){
	if(input!=NULL){
		int size = strlen(input);
	    char output[size];
	    for(int i=0;i<size;i++){
	    	output[i] = input[i] ^ key[i];
	    }
	    strcpy(ptr,output);
	}
}
//-------------------------------------------------------------





//-------------------------------------------------------------
void caesarCipherEncrypt(char * input,int key,char *ptr){
	int size = strlen(input);
	int min,max;
	min = 48;
	max = 122;
	char output[size];
	key = key%(max-min);
	for(int i=0;i<size;i++){
		if(input[i]+key>max)
			output[i] = min + (input[i]+key-max);
		else
			output[i] = input[i] + key;
	}
	strcpy(ptr,output);
}

void caesarCipherDecrypt(char * input,int key,char *ptr){
	int size = strlen(input);
	int min,max;
	min = 48;
	max = 122;
	char output[size];
	key = key%(max-min);
	for(int i=0;i<size;i++){
		if(input[i]-key<min)
			output[i] = max - ( min - (input[i]-key) );
		else
			output[i] = input[i] - key;
	}
	strcpy(ptr,output);
}
//-------------------------------------------------------------




//-------------------------------------------------------------
void vigenereCipherEncrypt(char * input,char * key,char *ptr){
	int sizeInput = strlen(input);
	int sizeKey = strlen(key);
	int j=0;
	int diffRow,diffCol,num;
	int min = 65;
	int max =90;
	char output[sizeInput];
	for(int i=0;i<sizeInput;i++){
		if(j==sizeKey)
			j=0;
		diffRow = input[i] - min;
		diffCol = key[j] - min;
		num = min + diffRow + diffCol;
		if(num>max)
			output[i] = min - 1 + (num-max);
		else
			output[i] = num;
		j++;
	}
	strcpy(ptr,output);
}
void vigenereCipherDecrypt(char * input,char * key,char *ptr){
	int sizeInput = strlen(input);
	int sizeKey = strlen(key);
	int j=0;
	int diff,num;
	int min = 65;
	int max =90;
	char output[sizeInput];
	for(int i=0;i<sizeInput;i++){
		if(j==sizeKey)
			j=0;
		diff = key[j] - min;
		num=input[i]-diff;
		if(num<min)
			output[i] = max + 1 - (min-num);
		else
			output[i] = num;
		j++;
	}
	strcpy(ptr,output);
}
//-------------------------------------------------------------





//--------------- Help Functions -------------------



struct minMax findMinMax(char *input){
	struct minMax myMinMax;
	int min =  99999;
	int max = -99999;
	int size = strlen(input);
	for(int i=0;i<size;i++){
		if(min > input[i])
			min = input[i];
		if(max < input[i])
			max = input[i];
	}
	myMinMax.min = min;
	myMinMax.max = max;
	return myMinMax;
}

void printEncryptedKey(int mySize,char * input,int a,int b){
	struct minMax myMinMax = findMinMax(input);
	int cur;
	printf("[OTP] encrypted: ");
	for(int j=0;j<mySize;j++){
		cur = ( (b-a)*(input[j]-myMinMax.min) ) / ( myMinMax.max - myMinMax.min ) ;
		cur+=a;
		printf("%c",cur );
	}
	printf("\n");
}

void getRandomKey(int length,char *ptr){
    char data[length];
    char output[length];
    FILE *fp;
    fp = fopen("/dev/urandom", "r");
    fread(&data, 1, length, fp);
    fclose(fp);
    struct minMax myMinMax = findMinMax(data);
    int size = strlen(data);
    if(myMinMax.max == myMinMax.min){
    	if(data[0]<33 || data[0]>126)
    		output[0] = (data[0] % (126-33))+33;
    }else{
    	int a = 33;
	    int b = 126;
	    int cur;
	    for(int i=0;i<size;i++){
	    	cur = ( (b-a)*(data[i]-myMinMax.min) ) / ( myMinMax.max - myMinMax.min ) ;
	    	cur+=a;
	    	output[i] = cur;
	    }
    }
	strcpy(ptr,output);
}

char *inputString(FILE* fp, size_t size){
//The size is extended by the input with the value of the provisional
    char *str;
    int ch;
    int initial=1;
    size_t len = 0;
    str = realloc(NULL, sizeof(char)*size);//size is start size
    if(!str)return str;
    while(1){
    	if(!(EOF!=(ch=fgetc(fp)) && ch != '\n')){
    		if(initial==0)
    			break;
    	}
    	if(initial==1 && ch == '\n')
    		continue;
    	initial = 0;
        str[len++]=ch;
        if(len==size){
            str = realloc(str, sizeof(char)*(size+=16));
            if(!str)return str;
        }
    }
    str[len++]='\0';

    return realloc(str, sizeof(char)*len);
}

void demoOTP(){
	char *input;
	printf("Give a messege to encrypt: [OTP]\n");
	input = inputString(stdin, 10);
	long size = strlen(input);
	char answer[size+1];
	input[size] = '\0';
	char key[size];
	getRandomKey(size,key);
	oneTimePadEncrypt(input,key,answer);
	printEncryptedKey(size,answer,33,126);
	oneTimePadDecrypt(answer,key,answer);
	printf("[OTP] decrypted: ");
	for(int i=0;i<strlen(input);i++){
		printf("%c", answer[i]);
	}
	printf("\n");
}
void demoCC(){
	char *input;
	printf("Give a messege to encrypt: [Caesars]\n");
	input = inputString(stdin, 10);
	long sizeInput = strlen(input);
	char answer[sizeInput+1];
	input[sizeInput] = '\0';
	long key;
	printf("Give a key to use: [Caesars]\n");
	scanf("%ld", &key);
	printf("[Caesars] input: %s\n", input);
	printf("[Caesars] key: %ld\n", key);
	caesarCipherEncrypt(input,key,answer);
	printf("[Caesars] encrypted: ");
	for(long i=0;i<sizeInput;i++){
		printf("%c", answer[i]);
	}
	printf("\n");
	caesarCipherDecrypt(answer,key,answer);
	printf("[Caesars] decrypted: ");
	for(long i=0;i<sizeInput;i++){
		printf("%c", answer[i]);
	}
	printf("\n");
}

void demoVC(){
	char *input;
	char *key;
	printf("Give a messege to encrypt: [Vigenere]\n");
	input = inputString(stdin, 10);
	long sizeInput = strlen(input);
	char answer[sizeInput+1];
	input[sizeInput] = '\0';
	printf("Give a key to use: [Vigenere]\n");
	key = inputString(stdin, 10);
	//key[strlen(key)]='\0';
	printf("[Vigenere] input: %s\n", input);
	printf("[Vigenere] key: %s\n", key);
	vigenereCipherEncrypt(input,key,answer);
	printf("[Vigenere] encrypted: ");
	for(long i=0;i<sizeInput;i++){
		printf("%c", answer[i]);
	}
	printf("\n");
	vigenereCipherDecrypt(answer,key,answer);
	printf("[Vigenere] decrypted: ");
	for(long i=0;i<sizeInput;i++){
		printf("%c", answer[i]);
	}
	printf("\n");
}
