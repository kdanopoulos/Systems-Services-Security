
path := $(shell realpath monitor)

all: monitor

monitor: monitor.c 
	gcc monitor.c -lpcap -o monitor
	sudo setcap cap_net_raw,cap_net_admin,cap_dac_override+eip ${path}
clean:
	rm -rf monitor