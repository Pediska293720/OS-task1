#ifndef CAESAR_H
#define CAESAR_H

void caesar(void* src, void* dst, int len);
int set_key(char key);
int init_secure_key_storage(void);
void cleanup_secure_key(void);

#endif
