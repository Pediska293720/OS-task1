#include "cesare.h"

static unsigned char c_key;

void cesare(void* src, void* dst, int len){
    unsigned char* src_bytes = (unsigned char*)src;
    unsigned char* dst_bytes = (unsigned char*)dst;

    for (int i = 0; i < len; i++){
        dst_bytes[i] = src_bytes[i] ^ c_key; 
    }
}

void cesare_key(char key){
    c_key = (unsigned char)key;
}

