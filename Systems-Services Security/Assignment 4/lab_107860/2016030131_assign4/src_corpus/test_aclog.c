#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <sys/types.h>

int main() 
{
	int i;
	size_t bytes;
	FILE *file;
	char filenames[10][7] = {"file_0", "file_1", 
			"file_2", "file_3", "file_4",
			"file_5", "file_6", "file_7", 		
			"file_8", "file_9"};
	char texts[10][8] = {"koukoua", "pinelos", 
			"koupesd", "psematd", "elaresd",
			"toponid", "pomonid", "moponid", 		
			"eetonid", "kdvdgld"};


	/* example source code */

	for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
			fclose(file);
		}
	}



	file = fopen("no_perm1", "w+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
		fclose(file);
	}

	file = fopen("no_perm2", "w+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
		fclose(file);
	}

	file = fopen("no_perm3", "w+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
		fclose(file);
	}

	/*struct passwd *pw;
	printf("here\n");
	unsigned int userid = getuid();
	printf("%d\n", userid);
	printf("here1\n");
	pw = getpwuid(1001);
	//if((pw = getpwnam("1000")) == NULL)
    	//printf("Userid '%d' does not exist", userid);

	if (setgid(pw->pw_gid) != 0)
    	printf("setgid() to %d failed", pw->pw_gid);

	if (setuid(pw->pw_uid) != 0)
    	printf("setuid() to %d failed", pw->pw_uid);
*/
    for (i = 0; i < 10; i++) {

		file = fopen(filenames[i], "w+");
		if (file == NULL) 
			printf("fopen error\n");
		else {
			bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
			fclose(file);
		}
	}



	file = fopen("no_perm1", "w+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
		fclose(file);
	}

	file = fopen("no_perm2", "w+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
		fclose(file);
	}

	file = fopen("no_perm3", "w+");
	if (file == NULL) 
		printf("fopen error\n");
	else {
		bytes = fwrite(texts[i], strlen(texts[i]), 1, file);
		fclose(file);
	}


}
