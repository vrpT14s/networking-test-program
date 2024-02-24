CC=gcc
CFLAGS= -g -lnettle

run: main
	./main

debug: main
	gdb main

main: main.c
	$(CC) $(CFLAGS) $< -o $@
