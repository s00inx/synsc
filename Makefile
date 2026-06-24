all:
	gcc -O2 -Wall -Wextra -Iinclude $(wildcard src/*.c) $(wildcard *.c) -o synscan