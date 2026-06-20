all: 
	gcc -O2 -Wall -Wextra -Iinclude src/main.c src/send.c src/receive.c -o synscan