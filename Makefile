CC=gcc
STD=gnu11
TARGET=main

all:
	$(CC) --std=$(STD) -o $(TARGET) $(TARGET).c
