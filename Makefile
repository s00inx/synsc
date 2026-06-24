all:
	gcc -O2 -Wall -Wextra -Iinclude $(wildcard src/*.c) $(wildcard *.c) -o synscan

clean:
	rm -f ./synscan

.PHONY:
	all clean