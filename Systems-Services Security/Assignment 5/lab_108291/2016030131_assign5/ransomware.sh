#! /usr/bin/bash

args=("$@")

param=$#

if [[ "$param" -gt 2 ]]; then
	echo Error: unknown input
else
	directoy=$1
	num_of_files=$2
	#find "$directoy" -type f | shuf -n "$num_of_files"

	mapfile -d $'\0' array < <(find "$directoy" -type f) # | shuf -n "$num_of_files") #we encrypt num_of_files files randomly in the directory
	#echo $array

	for obj in $array
	do
		new_file=$obj
		new_file+=".encrypt"
		./assign_1 -i "$obj" -o "$new_file" -p 1234 -b 256 -e 
		#openssl enc -aes-256-ecb -in "$obj" -out "$new_file" -k 1234
		rm "$obj"
		#openssl aes-256-ecb -in "$new_file" -out "$obj" -d -k 1234
		#rm "$new_file"
	done

	for i in $(seq 1 "$num_of_files");
	do
    	mapfile -d $'\0' filename < <(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32)
    	finalName=$directoy
    	finalName+="/"
    	finalName+=$filename
    	touch "$finalName"
	done
fi

