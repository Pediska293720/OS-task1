#ifndef RC4_H
#define RC4_H

#include <stddef.h>
#include <stdint.h>

int init_secure_key_storage(void);
int set_key(const char* key, size_t key_len);
void cleanup_secure_key(void);
void rc4_crypt_with_salt(void* src, void* dst, int len, const uint8_t* salt, size_t salt_len);

#endif
