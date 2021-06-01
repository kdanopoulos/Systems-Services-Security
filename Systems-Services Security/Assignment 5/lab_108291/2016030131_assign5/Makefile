CC = gcc
DBUG = -g
CCFLAGS = -O2 -Wall -pedantic
LIBSSL = -lssl -lcrypto

all: logger acmonitor test_aclog assign_1

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog

assign_1: assign_1.c
	$(CC) $(CCFLAGS) $(DBUG) -o $@ $< $(LIBSSL)

run: logger.so test_aclog
	LD_PRELOAD=./logger.so ./test_aclog

bash: logger.so ransomware.sh
	LD_PRELOAD=./logger.so ./ransomware.sh files 100

clean:
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	rm -f assign_1

