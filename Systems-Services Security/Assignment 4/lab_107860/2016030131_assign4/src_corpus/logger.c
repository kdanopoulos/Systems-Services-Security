#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/md5.h>
#include <errno.h>
#include <string.h>

void getFile(char *filename){
	FILE *fp;
	FILE *(*original_fopen)(const char*, const char*);
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	fp = (*original_fopen)(filename, "rb");
	char myBuffer[1024];
	size_t elements;


	// Variables for MD-5 
	MD5_CTX context_MD5_CTX;
	unsigned char hash[MD5_DIGEST_LENGTH];
	*hash = NULL;
	int counter_MD5;
	char buffer[1024];
	// Variables for MD-5 // end

	MD5_Init(&context_MD5_CTX);
	while(elements = fread(myBuffer,1024, 1, fp)){
		printf("%s\n", myBuffer);
		MD5_Update(&context_MD5_CTX, myBuffer, elements);
	}
	MD5_Final(hash, &context_MD5_CTX);
	fclose(fp);
}

FILE *
fopen(const char *path, const char *mode) 
{
	//------------ My code ------------ // I check for access type _ and find file name
	char filename[1024];
	realpath(path, filename);  // find filename
	struct stat info;  
	int status_file_ret_val;
	status_file_ret_val = stat(filename,&info); // check if the file already exists
	int accessType = -1; // creation = 0 | file open = 1
	if(status_file_ret_val== -1){
		// file does not exists yet
		accessType = 0; // creation
	}else{
		accessType = 1; // file open
	}
	//------------ My code ------------ // end



	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	/* call the original fopen function */
	int is_action_denied = -1;
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);
	// call the original fopen function // end

	if(original_fopen_ret==NULL){
		is_action_denied = 1;
		printf("action is denied\n");
	}
	else{
		is_action_denied = 0;
	}



	//------------ My code ------------
	time_t rawtime;
	time(&rawtime);
	struct tm *timeinfo = localtime(&rawtime);
	char timestamp[80], date[80];
	strftime(timestamp, 80, "%T", timeinfo);      // find time
	strftime(date, 80, "%F",      timeinfo);      // find date
	unsigned int uid = (unsigned int) getuid();   // get uid
	FILE *fp;

	//getFile(filename);

	// Variables for MD-5 
	MD5_CTX context_MD5_CTX;
	unsigned char hash[MD5_DIGEST_LENGTH];
	*hash = NULL;
	int counter_MD5;
	char buffer[1024];
	// Variables for MD-5 // end

	status_file_ret_val = stat(filename,&info); // info for the file _ after fopen
	if(status_file_ret_val == -1){
		// file still does not exists
	}
	else{
		// file exists 
		fp = (*original_fopen)(path, "rb");
		MD5_Init(&context_MD5_CTX);
		char myBuffer[1024];
		size_t elements;
		if(fp!=NULL){
			while(elements = fread(myBuffer,1024, 1, fp)){
				MD5_Update(&context_MD5_CTX, myBuffer, elements);
			}
			MD5_Final(hash, &context_MD5_CTX);
			fclose(fp);
		}
	}





	/*FILE * (*open)(const char*,const char*);
	open = dlsym(RTLD_NEXT,"fopen");
	FILE *ptr = (*open)(path,"r");
	printf("fp = %d\n",ptr);
	char *ln;
	ssize_t sz;
	ssize_t rd = getline(&ln,&sz,ptr);
	printf("??????/ read = %d , line = %s , length = %d errno = %d\n",rd,ln,sz,errno);
	char *input;
	size_t kk;
	input = inputString(ptr,10);
	printf("%s\n", input);


	status_file_ret_val = stat(filename,&info); // info for the file _ after fopen
	if(status_file_ret_val == -1){
		// file still does not exists
	}
	/*else{
		// file exists 
		errno = -1;
		//fp = (*original_fopen)(filename, "rb");
		fp = originalFopen(filename,"rb");


		if(errno==0){ 
			MD5_Init(&context_MD5_CTX);
			char * line = NULL;
			size_t len = 0;
			ssize_t read;
			while ((read = getline(&line, &len, fp)) != -1){
				printf("Retrieved line of length %zu:\n", read);
        		printf("%s",line);
        		MD5_Update(&context_MD5_CTX, line, len);
			}
			printf("read =  %d\n", read);
			MD5_Final(hash, &context_MD5_CTX);
			fclose(fp);
		}
	}*/


	char text[10000];
	sprintf(text, "\n--------------------------------------------\n");
	sprintf(text + strlen(text), "UID :%d\n",uid);
	sprintf(text + strlen(text), "F​ile name​ :%s\n",filename);
	sprintf(text + strlen(text), "Date :%s\n",date);
	sprintf(text + strlen(text), "Timestamp :%s\n",timestamp);
	sprintf(text + strlen(text), "Access t​ype​ :%d\n",accessType);
	sprintf(text + strlen(text), "Is-a​ction-denied flag​ :%d\n",is_action_denied);
	if(errno==0){
		sprintf(text + strlen(text), "File fingerprint​ :");
		for(int i=0;i < MD5_DIGEST_LENGTH; i++){
			sprintf(text + strlen(text), "%02x", hash[i]);
		}
		sprintf(text + strlen(text), "\n");
	}
	else{
		sprintf(text + strlen(text), "File fingerprint​ :|An error has occurred while trying to open the file\n");
	}

	fp = (*original_fopen)("file_logging.log", "a");
	fputs(text, fp);
	fclose(fp);
	//------------ My code ------------ // end

	//printf("%s\n", text);

	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{
	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen"); // creating fopen that skips my preload functions

	// -------- finding file name from FILE pointer --------
	int max = 0xFFF;
    char link[0xFFF];
    char filename[0xFFF];
    ssize_t size_of_filename;
    int fileDescriptor;

	if (stream != NULL){
        fileDescriptor = fileno(stream); // find file descriptor
        sprintf(link, "/proc/self/fd/%d", fileDescriptor); // link  = /proc/self/fd/fileDescriptor
        size_of_filename = readlink(link, filename, max);
        if (size_of_filename < 0)
        {
            fprintf(stdout,"Error reading link...\n");
            exit(1);
        }
        filename[size_of_filename] = '\0';
    }
    // -------- finding file name from FILE pointer -------- \\ end


	int is_action_denied = -1;

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);
	if(original_fwrite_ret==0)
		is_action_denied = 1;
	else if(original_fwrite_ret>0)
		is_action_denied = 0;
	int accessType = 2; // file write


	//------------ My code ------------

	time_t rawtime;
	time(&rawtime);
	struct tm *timeinfo = localtime(&rawtime);
	char timestamp[80], date[80];
	strftime(timestamp, 80, "%T", timeinfo);     // find time
	strftime(date, 80, "%F",      timeinfo);     // find date
	//char filename[1024];
	//realpath(path, filename);    // find filename
	unsigned int uid = (unsigned int) getuid(); // get uid
	FILE *fp;

	// Variables for MD-5 
	MD5_CTX context_MD5_CTX;
	unsigned char hash[MD5_DIGEST_LENGTH];
	*hash = NULL;
	int counter_MD5;
	char buffer[1024];
	// Variables for MD-5 // end


	struct stat info;  
	int status_file_ret_val;
	status_file_ret_val = stat(filename,&info); // info for the file


	if(status_file_ret_val == -1){
		// file still does not exists
		is_action_denied = 1; // this line can be erased
	}
	else{
		// file exists 
		fp = (*original_fopen)(filename, "rb");
		MD5_Init(&context_MD5_CTX);
		/*char * line = NULL;
		size_t len = 0;
		ssize_t read;
		while ((read = getline(&line, &len, fp)) != -1){
			printf("Retrieved line of length %zu:\n", read);
        	printf("%s",line);
        	MD5_Update(&context_MD5_CTX, line, len);
		}*/
		while ((counter_MD5 = fread(buffer, 1, 1024, fp))){
			//printf("buffer = %s\n", buffer);
			MD5_Update(&context_MD5_CTX, buffer, counter_MD5);
		}
		MD5_Final(hash, &context_MD5_CTX);
		fclose(fp);
	}

	char text[10000];
	sprintf(text, "\n--------------------------------------------\n");
	sprintf(text + strlen(text), "UID :%d\n",uid);
	sprintf(text + strlen(text), "F​ile name​ :%s\n",filename);
	sprintf(text + strlen(text), "Date :%s\n",date);
	sprintf(text + strlen(text), "Timestamp :%s\n",timestamp);
	sprintf(text + strlen(text), "Access t​ype​ :%d\n",accessType);
	sprintf(text + strlen(text), "Is-a​ction-denied flag​ :%d\n",is_action_denied);
	if(errno==0){
		sprintf(text + strlen(text), "File fingerprint​ :");
		for(int i=0;i < MD5_DIGEST_LENGTH; i++){
			sprintf(text + strlen(text), "%02x", hash[i]);
		}
		sprintf(text + strlen(text), "\n");
	}
	else{
		sprintf(text + strlen(text), "File fingerprint​ :|An error has occurred while trying to open the file\n");
	}

	fp = (*original_fopen)("file_logging.log", "a");
	fputs(text, fp);
	fclose(fp);
	//------------ My code ------------ // end


	return original_fwrite_ret;
}


