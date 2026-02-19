CC = gcc
CFLAGS = -Wall -Wextra -pedantic -fPIC

caesar:
	$(CC) main.c -o caesar

lib:
	$(CC) $(CFLAGS) -c caesar.c -o caesar.o
	$(CC) $(CFLAGS) -shared caesar.c -o libcaesar.so

test:
	echo "Hello, World! This is a test file." > test_input.txt
	./caesar ./libcaesar.so A test_input.txt test_encrypted.txt
	@cat test_encrypted.txt
	@echo ""
	./caesar ./libcaesar.so A test_encrypted.txt test_decrypted.txt
	@cat test_decrypted.txt
	@echo ""

install: 
	sudo cp libcesar.so /usr/local/lib/

