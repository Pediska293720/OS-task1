#include "caesar.h"
#include <sys/mman.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>

static unsigned char* secure_key_ptr = NULL;
static size_t page_size = 4096;


int init_secure_key_storage(void) {
    secure_key_ptr = mmap(NULL, page_size, PROT_NONE, 
                         MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (secure_key_ptr == MAP_FAILED) {
        secure_key_ptr = NULL;
        return -1;
    }

    return 0;
}

int set_key(char key){
    if (secure_key_ptr == NULL) return -1;
    
    if (mprotect(secure_key_ptr, page_size, PROT_READ | PROT_WRITE) == -1)
        return -1;
    
    secure_key_ptr[0] = (unsigned char)key;

    __asm__ volatile ("mfence" ::: "memory");

    if (mprotect(secure_key_ptr, page_size, PROT_NONE) == -1)
        return -1;
    
    return 0;
}

static unsigned char get_key(void) {
    if (secure_key_ptr == NULL) return 0;

    if (mprotect(secure_key_ptr, page_size, PROT_READ) == -1) return 0;
    
    unsigned char key = secure_key_ptr[0];
    
    __asm__ volatile ("lfence" ::: "memory");
    mprotect(secure_key_ptr, page_size, PROT_NONE);
    
    return key;
}

void cleanup_secure_key(void) {
    if (secure_key_ptr == NULL) return;
    
    mprotect(secure_key_ptr, page_size, PROT_READ | PROT_WRITE);
    
    memset(secure_key_ptr, 0, page_size);
    __asm__ volatile ("mfence" ::: "memory");
    
    munmap(secure_key_ptr, page_size);
    secure_key_ptr = NULL;
}

void caesar(void* src, void* dst, int len){
    unsigned char* src_bytes = (unsigned char*)src;
    unsigned char* dst_bytes = (unsigned char*)dst;

    unsigned char c_key = get_key();

    for (int i = 0; i < len; i++){
        dst_bytes[i] = src_bytes[i] ^ c_key; 
    }
}



