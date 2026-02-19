#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>

 
int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("%s <lib> <key> <src_file> <dst_file>\n", argv[0]);
        return 1;
    }
    
    char* lib = argv[1];
    void* library = dlopen(lib, RTLD_LAZY);

    void (*cesare)(void*, void*, int) = dlsym(library, "cesare");
    void (*cesare_key)(char) = dlsym(library, "cesare_key");

    char key = argv[2][0];
    cesare_key(key);
    
    FILE* src_file = fopen(argv[3], "rb");
    
    fseek(src_file, 0, SEEK_END);
    long file_size = ftell(src_file);
    rewind(src_file);
    
    unsigned char *buffer = (unsigned char*)malloc(file_size);
    unsigned char *result = (unsigned char*)malloc(file_size);
    
    fread(buffer, 1, file_size, src_file);
    cesare(buffer, result, file_size);
    
    FILE* dst_file = fopen(argv[4], "wb");
    fwrite(result, 1, file_size, dst_file);
    
    free(buffer);
    free(result);
    fclose(src_file);
    fclose(dst_file);
    dlclose(library); 
    return 0;
}
