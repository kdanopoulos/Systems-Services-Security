
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	char *date; /* file access date */
	char *time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	/* add here other fields if necessary */
	/* ... */
	/* ... */
	struct entry *next;
};

struct users {
	unsigned int uid;
	unsigned int no_permission_accesses;
	struct users *next;
};

void freeLogEntries(struct entry *);
struct entry *addLogEntry(struct entry *,int,int,int,time_t,time_t,char *,char *);
struct users *addOneDeniedAccess(struct users *,unsigned int);
void freeUsers(struct users *);
int isNewUser(struct users *,unsigned int);
struct users *addUser(struct users *,unsigned int,unsigned int);
struct entry *readLogFile(FILE *);
struct users *createListOfUsersFromLogEntries(struct entry *);
struct users *createModificationUsersOfFile(struct entry *);


void freeLogEntries(struct entry *head){
	struct entry *prev;
	prev = head;
	while(head!=NULL){
		head=head->next;
		free(prev->file);
		free(prev->fingerprint);
		free(prev);
		prev = head;
	}
}

struct entry *addLogEntry(struct entry *head,int uid,int access_type,int action_denied,time_t date,time_t time,char *file,char *fingerprint){
	struct entry *cur;
	cur = head;
	if(head==NULL){ // list is empty
		head = malloc(sizeof(struct entry));
		head->uid=uid;
		head->access_type=access_type;
		head->action_denied=action_denied;
		head->date=date;
		head->time=time;
		head->file=malloc(strlen(file)*sizeof(char));
		strcpy(head->file,file);
		head->fingerprint=malloc(strlen(fingerprint)*sizeof(char));
		strcpy(head->fingerprint,fingerprint);
		head->next = NULL;
	}
	else{
		while(cur->next!=NULL){
			cur =  cur->next;
		}
		cur->next = malloc(sizeof(struct entry));
		cur=cur->next;
		cur->uid=uid;
		cur->access_type=access_type;
		cur->action_denied=action_denied;
		cur->date=date;
		cur->time=time;
		cur->file=malloc(strlen(file)*sizeof(char));
		strcpy(cur->file,file);
		cur->fingerprint=malloc(strlen(fingerprint)*sizeof(char));
		strcpy(cur->fingerprint,fingerprint);
		cur->next = NULL;
	}
	return head;
}

struct users *addOneDeniedAccess(struct users *head,unsigned int uid){
	struct users *cur;
	cur=head;
	while(cur->uid!=uid){
		cur=cur->next;
	}
	cur->no_permission_accesses = cur->no_permission_accesses + 1; 
	return head;
}

void freeUsers(struct users *head){
	struct users *prev;
	prev = head;
	while(head!=NULL){
		head=head->next;
		free(prev);
		prev = head;
	}
}

int isNewUser(struct users *head,unsigned int curUID){
	if(head==NULL)
		return 1;
	else{
		while(head!=NULL){
			if(head->uid==curUID)
				return 0;
			head = head->next;
		}
	}
	return 1;
}

struct users *addUser(struct users *head,unsigned int cur_uid,unsigned int accesses){
	struct users *cur;
	cur = head;
	if(head==NULL){ // list is empty
		head = malloc(sizeof(struct users));
		head->uid = cur_uid;
		head->no_permission_accesses = accesses;
		head->next = NULL;
	}
	else{
		while(cur->next!=NULL){
			cur =  cur->next;
		}
		cur->next = malloc(sizeof(struct users));
		cur=cur->next;
		cur->uid = cur_uid;
		cur->no_permission_accesses = accesses;
		cur->next = NULL;
	}
	return head;
}
struct entry *readLogFile(FILE *log){
	struct entry *list_of_entries;
	list_of_entries = NULL;

	char * line = NULL;
	char * variable = NULL;
    size_t len = 0;
    unsigned int i = 0;
    ssize_t read;
    struct entry log_entry;

    char buffer_file[10000];
    char buffer_date[10000];
    char buffer_time[10000];
    char buffer_fingerprint[10000];


    //struct tm tm;
	//time_t t;

    while ((read = getline(&line, &len, log)) != -1) {
        //printf("Retrieved line of length %zu:\n", read);
        //printf("%d. %s", i,line);

       if(i>1){
        	variable = strtok(line, ":");
        	variable = strtok(NULL, "\n");
        	//printf("++++++ = %s\n", variable);
        	if(i==2)
        		log_entry.uid = atoi(variable);
        	else if(i==3){
        		//log_entry.file = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.file,variable);
        		strcpy(buffer_file,variable);
        	}
        	else if(i==4){
        		//log_entry.date = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.date,variable);
        		strcpy(buffer_date,variable);
        		/*
        		char *y = atoi(strtok(variable, "-"));
        		char *m = atoi(strtok(NULL, "-"));
        		char *d = atoi(strtok(NULL, "-"));
        		tm.tm_year = y;
        		tm.tm_mon = m;
        		tm.tm_mday = d;
        		//strptime(variable, "%Y:%m:%d", &tm);
        		t = mktime(&tm);
        		log_entry.date = t;*/
        	}
        	else if(i==5){
        		//log_entry.time = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.time,variable);
        		strcpy(buffer_time,variable);
        		/*strptime(variable, "%H:%M:%S", &tm);
        		t = mktime(&tm);
        		log_entry.time = t;*/
        	}
        	else if(i==6)
        		log_entry.access_type = atoi(variable);
        	else if(i==7)
        		log_entry.action_denied = atoi(variable);
        	else if(i==8){
        		//log_entry.fingerprint = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.fingerprint,variable);
        		strcpy(buffer_fingerprint,variable);
        	}
        }
        if(i==8){
        	i=0;
        	list_of_entries = addLogEntry(list_of_entries,log_entry.uid,log_entry.access_type,log_entry.action_denied, buffer_date , buffer_time , buffer_file , buffer_fingerprint );
        	//list_of_entries = addLogEntry(list_of_entries,log_entry.uid,log_entry.access_type,log_entry.action_denied,log_entry.date,log_entry.time,log_entry.file,log_entry.fingerprint);
        	//free(log_entry.file);
        	//free(log_entry.fingerprint);
        	//free(log_entry.date);
        	//free(log_entry.time);
        }
        else
        	i++;
    }
    return list_of_entries;
}
struct entry *createListOfLogsOfSpecificFile(FILE *log,char *filename){
	struct entry *list_of_entries;
	list_of_entries = NULL;

	char * line = NULL;
	char * variable = NULL;
    size_t len = 0;
    unsigned int i = 0;
    ssize_t read;
    struct entry log_entry;


    char buffer_file[10000];
    char buffer_date[10000];
    char buffer_time[10000];
    char buffer_fingerprint[10000];

    while ((read = getline(&line, &len, log)) != -1) {
        //printf("Retrieved line of length %zu:\n", read);
        //printf("%d. %s", i,line);

       if(i>1){
        	variable = strtok(line, ":");
        	variable = strtok(NULL, "\n");
        	//printf("++++++ = %s\n", variable);
        	if(i==2)
        		log_entry.uid = atoi(variable);
        	else if(i==3){
        		//log_entry.file = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.file,variable);
        		strcpy(buffer_file,variable);
        	}
        	else if(i==4){
        		//log_entry.date = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.date,variable);
        		strcpy(buffer_date,variable);
        		/*struct tm tm;
        		strptime(variable, "%Y:%m:%d", &tm);
        		time_t t = mktime(&tm);
        		log_entry.date = t;*/
        	}
        	else if(i==5){
        		//log_entry.time = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.time,variable);
        		strcpy(buffer_time,variable);
        		/*struct tm tm;
        		strptime(variable, "%H:%M:%S", &tm);
        		time_t t = mktime(&tm);
        		log_entry.time = t;*/
        	}
        	else if(i==6)
        		log_entry.access_type = atoi(variable);
        	else if(i==7)
        		log_entry.action_denied = atoi(variable);
        	else if(i==8){
        		//log_entry.fingerprint = malloc(strlen(variable)*sizeof(char));
        		//strcpy(log_entry.fingerprint,variable);
        		strcpy(buffer_fingerprint,variable);
        	}
        }
        if(i==8){
        	i=0;
        	//printf("input user = %s\n", filename);
        	//printf("current file = %s\n", log_entry.file);
        	if( strcmp(log_entry.file,filename)==0 && ( log_entry.access_type==0 || log_entry.access_type==2 ) ){
        		//list_of_entries = addLogEntry(list_of_entries,log_entry.uid,log_entry.access_type,log_entry.action_denied,log_entry.date,log_entry.time,log_entry.file,log_entry.fingerprint);
        		list_of_entries = addLogEntry(list_of_entries,log_entry.uid,log_entry.access_type,log_entry.action_denied, buffer_date , buffer_time , buffer_file , buffer_fingerprint );
        	}
        	//free(log_entry.file);
        	//free(log_entry.fingerprint);
        	//free(log_entry.date);
        	//free(log_entry.time);
        }
        else
        	i++;
    }
    return list_of_entries;
}

struct users *createListOfUsersFromLogEntries(struct entry *list_of_log_entries){
	struct users *list_of_users;
	list_of_users = NULL;
	while(list_of_log_entries!=NULL){
		if(list_of_log_entries->action_denied==1){
			// we have one permission denied
			if(isNewUser(list_of_users,list_of_log_entries->uid)){
				// we have a new user and we should add him to the list with one permission
				list_of_users = addUser(list_of_users, list_of_log_entries->uid , 1);
			}
			else{
				// this user is already at the list and we should add one permision for him
				list_of_users = addOneDeniedAccess(list_of_users, list_of_log_entries->uid );
			}
		}
		list_of_log_entries=list_of_log_entries->next;
	}
	return list_of_users;
}
struct users *createModificationUsersOfFile(struct entry *this_file_log_entries){
	struct users *list_of_users;
	struct entry *prev;
	list_of_users = NULL;
	prev = NULL;
	while(this_file_log_entries!=NULL){
		if(this_file_log_entries->access_type==0){  // current = create ----------------------------
			// add one modification at the user
			if(isNewUser(list_of_users,this_file_log_entries->uid)){
				// we have a new user and we should add him to the list with one modification
				list_of_users = addUser(list_of_users, this_file_log_entries->uid , 1);
			}
			else{
				// this user is already at the list and we should add one modification for him
				list_of_users = addOneDeniedAccess(list_of_users, this_file_log_entries->uid );
			}
		}
		//-------------------------------------------------------------------------------------------


		else if(this_file_log_entries->access_type==2){  // current = write -------------------------
			if(prev==NULL){
				printf("Error, couldn't find previous. The list in't complete\n");
				return NULL;
			}
			else{
				// we have fwrite
				// we should check if endeed the user changed the file
				if(strcmp(this_file_log_entries->fingerprint, prev->fingerprint)!=0){//the hashes are not the same
					// add one modification at the user
					if(isNewUser(list_of_users,this_file_log_entries->uid)){
						// we have a new user and we should add him to the list with one modification
						list_of_users = addUser(list_of_users, this_file_log_entries->uid , 1);
					}
					else{
						// this user is already at the list and we should add one modification for him
						list_of_users = addOneDeniedAccess(list_of_users, this_file_log_entries->uid );
					}
				}
			}
		}
		//-------------------------------------------------------------------------------------------


		prev = this_file_log_entries;
		this_file_log_entries = this_file_log_entries->next;
	}
	return list_of_users;
}

void
usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m, Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	int print=1;
	struct entry *list_of_log_entries;
	list_of_log_entries = readLogFile(log);

	struct users *list_of_users;
	list_of_users = createListOfUsersFromLogEntries(list_of_log_entries);

	struct users *cur;
	cur = list_of_users;
	printf("\nANSWER:\n\n");
	if(list_of_users==NULL){
		printf("No one user tried to have access in some file without a permission\n");
		print = 0;
	}
	else{
		while(cur!=NULL){
		if(cur->no_permission_accesses>7){
			printf("The user : %d accessed files without permission more than 7 times\n",cur->uid);
			print = 0;
		}
		cur=cur->next;
		}
	}
	if(print)
		printf("No one accessed files without permission more than 7 times\n");
	freeLogEntries(list_of_log_entries);
	freeUsers(list_of_users);
	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{
	printf("\nFile :%s\n",file_to_scan);
	sprintf(file_to_scan+strlen(file_to_scan),"!");

	struct entry *list_of_log_entries_of_this_file;
	list_of_log_entries_of_this_file = createListOfLogsOfSpecificFile(log,file_to_scan);
	/*struct entry *temp;
	temp = list_of_log_entries_of_this_file;
	if(temp==NULL)
		printf("list is NULL\n");
	else{
		while(temp!=NULL){
			printf("user = %d access_type = %d\n",temp->uid,temp->access_type);
			temp = temp->next;
		}
	}*/

	struct users *list_of_users;
	list_of_users = createModificationUsersOfFile(list_of_log_entries_of_this_file);

	struct users *cur;
	cur = list_of_users;
	printf("\nANSWER:\n\n");
	if(list_of_users==NULL){
		printf("No one has modified this file\n");
	}
	else{
		while(cur!=NULL){
			printf("The user : %d has modified the file : %d times\n",cur->uid,cur->no_permission_accesses);
			cur = cur->next;
		}
	}

	freeLogEntries(list_of_log_entries_of_this_file);
	freeUsers(list_of_users);
	return;
}


int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		printf("Error opening log file \"%s\"\n", "./log");
		return 1;
	}

	while ((ch = getopt(argc, argv, "hi:m")) != -1) {
		switch (ch) {		
		case 'i':
			list_file_modifications(log, optarg);
			break;
		case 'm':
			list_unauthorized_accesses(log);
			break;
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
