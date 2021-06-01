#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Configure adblock rules based on the domain names of $domainNames file.
        # Write your code here...
        echo 'Please wait while we collect the ips of the given domain names'
        countIp=0
        #ipList[countIp]=''
        while read line
        do 
        	hostAnwser=$(dig +short $line | grep '^[.0-9]*$')
        	for obj in $hostAnwser
        	do
        		#echo $obj
        		iptables -A INPUT -s $obj -j REJECT
        		#ipList[countIp]=$obj
        		countIp=$((countIp+1))
        	done
        done < $domainNames
        echo "Total: $countIp ips were collected!"
        #printf "%s\n" "${ipList[@]}" > IPAddresses.txt
        #echo 'ips were saved at the file succefully!'


        true
            
    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        # Write your code here...
        while read line
        do
        	iptables -A INPUT -s $line -j REJECT
        done < $IPAddresses
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        # Write your code here...
        iptables-save > $adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        # Write your code here...
        iptables-restore < $adblockRules
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
        # Write your code here...
        iptables -F INPUT
        iptables -P INPUT ACCEPT
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        # Write your code here...
        iptables -L
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0