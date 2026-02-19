CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC

all: caesar.o libcaesar.so caesar

caesar.o: caesar.c
	$(CC) $(CFLAGS) -c $< -o $@

libcaesar.so: caesar.o
	$(CC) -shared $^ -o $@

caesar: main.c
	$(CC) main.c -o $@ -ldl


test:
	echo "Hello, World! This is a test file." > test_input.txt
	./caesar ./libcaesar.so A test_input.txt test_encrypted.txt
	@cat test_encrypted.txt
	@echo ""
	./caesar ./libcaesar.so A test_encrypted.txt test_decrypted.txt
	@cat test_decrypted.txt
	@echo ""

install: 
	sudo cp libcaesar.so /usr/local/lib/

