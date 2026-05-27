#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <dlfcn.h>
#include <errno.h>
#include <time.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <stdint.h> 

#define BUFFER_SIZE 4096
#define TIMEOUT_SECONDS 5
#define WORKERS_COUNT 4
#define SALT_SIZE 16

static FILE *log_file = NULL;
static volatile int keep_running = 1;
static volatile int interruption_received = 0;
static pthread_mutex_t container_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;
static char* container_path = NULL;

static void (*rc4_crypt_with_salt)(void*, void*, int, const uint8_t*, size_t) = NULL;
static int (*init_secure_key_storage)(void) = NULL;
static int (*set_key)(const char*, size_t) = NULL;
static void (*cleanup_secure_key)(void) = NULL;

typedef struct {
    uint32_t data_len;
    uint32_t name_len;
    uint8_t salt[SALT_SIZE];
} file_header_t;

typedef struct {
    char *full_path;
    char *relative_path;
} file_entry_t;

typedef struct {
    file_entry_t *input_files;         
    int total_files;               
    int *current_file_index;                                  
    volatile int *running;         
    pthread_mutex_t *file_mutex;   
    FILE *log_file;                
    pthread_mutex_t *log_mutex;    
    int thread_id;
} thread_data_t;  

void get_timestamp(char *buffer, size_t size) {
    time_t rawtime;
    struct tm *timeinfo;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", timeinfo);
}

void log_operation(FILE *log_file, pthread_mutex_t *log_mutex, int thread_id, 
                   const char *filename, const char *status) {
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    
    if (log_mutex){
        pthread_mutex_lock(log_mutex);
    }
    fprintf(log_file, "[%s] Поток %d: %s - %s\n",
            timestamp, thread_id, filename, status);
    fflush(log_file);
    if (log_mutex){
        pthread_mutex_unlock(log_mutex);
    }
}

int load_rc4_library() {
    void *lib_handle = dlopen("./librc4.so", RTLD_LAZY);
    if (!lib_handle) {
        printf("Ошибка загрузки librc4.so: %s\n", dlerror());
        return -1;
    }
    
    *(void**)(&rc4_crypt_with_salt) = dlsym(lib_handle, "rc4_crypt_with_salt");
    *(void**)(&init_secure_key_storage) = dlsym(lib_handle, "init_secure_key_storage");
    *(void**)(&set_key) = dlsym(lib_handle, "set_key");
    *(void**)(&cleanup_secure_key) = dlsym(lib_handle, "cleanup_secure_key");    
    
    return 0;
}

void generate_salt(uint8_t *salt, size_t size) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        read(fd, salt, size);
        close(fd);
    } else {
        srand(time(NULL));
        for (size_t i = 0; i < size; i++) {
            salt[i] = rand() & 0xFF;
        }
    }
}

file_entry_t* get_next_file(thread_data_t *data) {
    struct timespec timeout;
    clock_gettime(CLOCK_REALTIME, &timeout);
    timeout.tv_sec += TIMEOUT_SECONDS;
    
    int lock_result = pthread_mutex_timedlock(data->file_mutex, &timeout);
    
    if (lock_result == ETIMEDOUT) {
        printf("Возможная взаимоблокировка: поток %d ожидает мьютекс >5 сек\n", 
               data->thread_id);
        return NULL;
    }
    
    if (lock_result != 0) {
        return NULL;
    }
    
    file_entry_t *next_file = NULL;
    if (*data->current_file_index < data->total_files) {
        next_file = &data->input_files[*data->current_file_index];
        (*data->current_file_index)++;
    }
    
    pthread_mutex_unlock(data->file_mutex);
    return next_file;
}

int file_exists_in_container(const char *filename) {
    int fd = open(container_path, O_RDONLY);
    if (fd < 0) return 0;
    
    file_header_t h;
    while (read(fd, &h, sizeof(h)) == sizeof(h)) {
        char *name = malloc(h.name_len + 1);
        read(fd, name, h.name_len);
        name[h.name_len] = '\0';
        
        if (strcmp(name, filename) == 0) {
            free(name);
            close(fd);
            return 1;
        }
        free(name);
        lseek(fd, h.data_len, SEEK_CUR);
    }
    close(fd);
    return 0;
}

int append_file_to_container(const char *filename, const char *relative_name) {
    if (file_exists_in_container(relative_name)) {
        return -2;
    }
    if (strlen(relative_name) > 4096) {
        printf("Ошибка: слишком длинное имя файла (%s)\n", relative_name);
        return -1;
    }
    
    int container_fd = open(container_path, O_RDWR);
    if (container_fd < 0) {
        container_fd = open(container_path, O_RDWR | O_CREAT, 0644);
        if (container_fd < 0) {
            printf("Ошибка открытия/создания образа\n");
            return -1;
        }
    }
    
    lseek(container_fd, 0, SEEK_END);
    
    int input_fd = open(filename, O_RDONLY);
    if (input_fd < 0) {
        printf("Ошибка открытия файла: %s\n", filename);
        close(container_fd);
        return -1;
    }
    
    struct stat st;
    if (fstat(input_fd, &st) != 0) {
        printf("Ошибка получения информации о файле: %s\n", filename);
        close(input_fd);
        close(container_fd);
        return -1;
    }
    
    if (st.st_size == 0) {
        printf("Предупреждение: файл %s пуст, пропускаем\n", relative_name);
        close(input_fd);
        close(container_fd);
        return -1;
    }
    
    uint32_t data_len = st.st_size;
    uint32_t name_len = strlen(relative_name);
    
    uint8_t salt[SALT_SIZE];
    generate_salt(salt, SALT_SIZE);
    
    file_header_t header;
    header.data_len = data_len;
    header.name_len = name_len;
    memcpy(header.salt, salt, SALT_SIZE);
    
    if (write(container_fd, &header, sizeof(header)) != sizeof(header)) {
        printf("Ошибка записи заголовка для: %s\n", relative_name);
        close(input_fd);
        close(container_fd);
        return -1;
    }
    
    if (write(container_fd, relative_name, name_len) != (ssize_t)name_len) {
        printf("Ошибка записи имени файла: %s\n", relative_name);
        close(input_fd);
        close(container_fd);
        return -1;
    }
    
    uint8_t *buffer = malloc(BUFFER_SIZE);
    uint8_t *encrypted = malloc(BUFFER_SIZE);
    
    if (!buffer || !encrypted) {
        printf("Ошибка выделения памяти\n");
        free(buffer);
        free(encrypted);
        close(input_fd);
        close(container_fd);
        return -1;
    }
    
    ssize_t bytes_read;
    int success = 0;
    
    while ((bytes_read = read(input_fd, buffer, BUFFER_SIZE)) > 0) {
        rc4_crypt_with_salt(buffer, encrypted, bytes_read, salt, SALT_SIZE);
        
        if (write(container_fd, encrypted, bytes_read) != bytes_read) {
            printf("Ошибка записи данных для: %s\n", relative_name);
            success = -1;
            break;
        }
    }
    
    if (bytes_read < 0) {
        printf("Ошибка чтения файла: %s\n", relative_name);
        success = -1;
    }
    
    free(buffer);
    free(encrypted);
    close(input_fd);
    close(container_fd);
    
    return success;
}

int list_files_in_container(void) {
    int container_fd = open(container_path, O_RDONLY);
    if (container_fd < 0) {
        printf("Ошибка открытия образа\n");
        return -1;
    }
    
    typedef struct {
        char *name;
        uint32_t size;
        uint8_t salt[SALT_SIZE];
        off_t data_offset;
    } list_entry_t;
    
    list_entry_t *entries = NULL;
    int entry_count = 0;
    
    file_header_t header;
    ssize_t bytes_read;
    
    while ((bytes_read = read(container_fd, &header, sizeof(header))) == sizeof(header)) {
        // Проверка валидности
        if (header.name_len > 4096 || header.data_len > 1024*1024*1024) {
            printf("Образ поврежден: некорректный заголовок\n");
            break;
        }
        
        char *name = malloc(header.name_len + 1);
        if (!name) break;
        
        if (read(container_fd, name, header.name_len) != (ssize_t)header.name_len) {
            free(name);
            break;
        }
        name[header.name_len] = '\0';
        
        entries = realloc(entries, (entry_count + 1) * sizeof(list_entry_t));
        entries[entry_count].name = strdup(name);
        entries[entry_count].size = header.data_len;
        memcpy(entries[entry_count].salt, header.salt, SALT_SIZE);
        entries[entry_count].data_offset = lseek(container_fd, 0, SEEK_CUR);
        entry_count++;
        
        free(name);
        lseek(container_fd, header.data_len, SEEK_CUR);
    }
    
    if (entry_count == 0) {
        printf("\nОбраз пуст\n");
        close(container_fd);
        return 0;
    }
    
    // Сортировка по имени
    for (int i = 0; i < entry_count - 1; i++) {
        for (int j = i + 1; j < entry_count; j++) {
            if (strcmp(entries[i].name, entries[j].name) > 0) {
                list_entry_t tmp = entries[i];
                entries[i] = entries[j];
                entries[j] = tmp;
            }
        }
    }
    
    printf("\nФайлы в образе:\n");
    printf("%-10s %-30s %s\n", "Размер", "Имя", "Превью (первые 32 байта)");
    printf("%-10s %-30s %s\n", "------", "----", "------------------------\n");
    
    uint8_t *buffer = malloc(64);
    uint8_t *decrypted = malloc(64);
    
    for (int i = 0; i < entry_count && i < 50; i++) {  // Ограничим вывод 50 файлами
        printf("%-10u %-30s ", entries[i].size, entries[i].name);
        
        // Читаем первые 32 байта файла
        lseek(container_fd, entries[i].data_offset, SEEK_SET);
        
        int preview_len = entries[i].size < 32 ? entries[i].size : 32;
        if (preview_len > 0) {
            read(container_fd, buffer, preview_len);
            rc4_crypt_with_salt(buffer, decrypted, preview_len, entries[i].salt, SALT_SIZE);
            
            for (int j = 0; j < preview_len && j < 32; j++) {
                if (decrypted[j] >= 32 && decrypted[j] <= 126) {
                    printf("%c", decrypted[j]);
                } else {
                    printf(".");
                }
            }
        }
        printf("\n");
        
        free(entries[i].name);
    }
    
    free(buffer);
    free(decrypted);
    
    printf("\n----------------------------------------\n");
    printf("Всего файлов: %d\n", entry_count);
    
    if (entry_count > 50) {
        printf("(показано первых 50 файлов)\n");
    }
    
    free(entries);
    close(container_fd);
    return 0;
}

int extract_file_from_container(const char *filename, const char *output_path) {
    int container_fd = open(container_path, O_RDONLY);
    if (container_fd < 0) {
        printf("Ошибка открытия образа\n");
        return -1;
    }
    
    file_header_t header;
    ssize_t bytes_read;
    int found = 0;
    off_t data_offset = 0;
    uint8_t found_salt[SALT_SIZE];
    uint32_t found_data_len = 0; 
    
    while ((bytes_read = read(container_fd, &header, sizeof(header))) == sizeof(header)) {
        // Проверка на валидность заголовка
        if (header.name_len > 4096 || header.data_len > 1024*1024*1024) {  // Максимум 1GB
            printf("Ошибка: некорректный заголовок файла\n");
            break;
        }
        
        char *name = malloc(header.name_len + 1);
        if (!name) {
            close(container_fd);
            return -1;
        }
        
        if (read(container_fd, name, header.name_len) != (ssize_t)header.name_len) {
            free(name);
            break;
        }
        name[header.name_len] = '\0';
        
        if (strcmp(name, filename) == 0) {
            found = 1;
            memcpy(found_salt, header.salt, SALT_SIZE);
            found_data_len = header.data_len;           
            data_offset = lseek(container_fd, 0, SEEK_CUR);
            free(name);
            break;
        }
        
        free(name);
        lseek(container_fd, header.data_len, SEEK_CUR);
    }
    
    if (!found) {
        printf("Файл не найден: %s\n", filename);
        close(container_fd);
        return -1;
    }
    
    // Проверка на пустой файл
    if (found_data_len == 0) {
        printf("Предупреждение: файл %s пуст\n", filename);
        close(container_fd);
        return 0;
    }
    
    lseek(container_fd, data_offset, SEEK_SET);
    
    int output_fd = open(output_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd < 0) {
        close(container_fd);
        printf("Ошибка создания выходного файла: %s\n", output_path);
        return -1;
    }
    
    uint8_t *buffer = malloc(BUFFER_SIZE);
    uint8_t *decrypted = malloc(BUFFER_SIZE);
    if (!buffer || !decrypted) {
        free(buffer);
        free(decrypted);
        close(container_fd);
        close(output_fd);
        return -1;
    }
    
    uint32_t remaining = found_data_len;
    int success = 0;
    
    while (remaining > 0) {
        ssize_t to_read = remaining < BUFFER_SIZE ? remaining : BUFFER_SIZE;
        ssize_t bytes_read_data = read(container_fd, buffer, to_read);
        if (bytes_read_data <= 0) {
            success = -1;
            break;
        }
        
        rc4_crypt_with_salt(buffer, decrypted, bytes_read_data, found_salt, SALT_SIZE);
        
        if (write(output_fd, decrypted, bytes_read_data) != bytes_read_data) {
            success = -1;
            break;
        }
        remaining -= bytes_read_data;
    }
    
    free(buffer);
    free(decrypted);
    close(container_fd);
    close(output_fd);
    
    if (success == 0) {
        printf("Файл извлечен: %s -> %s\n", filename, output_path);
        log_operation(log_file, &log_mutex, 0, filename, "ИЗВЛЕЧЕН");
        return 0;
    } else {
        printf("Ошибка при извлечении файла: %s\n", filename);
        return -1;
    }
}

void* file_processor_thread(void *arg) {
    thread_data_t *data = (thread_data_t*)arg;
    
    while (*data->running  && !interruption_received) {
        file_entry_t *input_file = get_next_file(data);
        if (!input_file) {
            pthread_mutex_lock(data->file_mutex);
            int all_processed = (*data->current_file_index >= data->total_files);
            pthread_mutex_unlock(data->file_mutex);
            
            if (all_processed) break;
            usleep(100000); 
            continue;
        }
        
        pthread_mutex_lock(&container_mutex);
        int result = append_file_to_container(input_file->full_path, input_file->relative_path);
        pthread_mutex_unlock(&container_mutex);
        
        if (result == 0) {
            printf("  + %s\n", input_file->relative_path);
            log_operation(data->log_file, data->log_mutex, data->thread_id, input_file->relative_path, "УСПЕХ");
        } 
        else if (result == -2){
            printf("Ошибка: файл %s уже существует в образе\n", input_file->relative_path);
            log_operation(data->log_file, data->log_mutex, data->thread_id, input_file->relative_path, "ОШИБКА");
        }
        else {
            printf("  ! ОШИБКА: %s\n", input_file->relative_path);
            log_operation(data->log_file, data->log_mutex, data->thread_id, input_file->relative_path, "ОШИБКА");
        }
    }   
    return NULL;
}

void collect_files_from_dir(const char *base_path, const char *relative_path, 
                            file_entry_t **files, int *count) {
    char full_path[1024];
    if (relative_path[0] == '\0') {
        snprintf(full_path, sizeof(full_path), "%s", base_path);
    } else {
        snprintf(full_path, sizeof(full_path), "%s/%s", base_path, relative_path);
    }
    
    struct stat st;
    if (lstat(full_path, &st) != 0) return;
    
    if (S_ISDIR(st.st_mode)) {
        DIR *dir = opendir(full_path);
        if (!dir) return;
        
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
            
            char new_rel_path[1024];
            if (relative_path[0] == '\0') {
                snprintf(new_rel_path, sizeof(new_rel_path), "%s", entry->d_name);
            } else {
                snprintf(new_rel_path, sizeof(new_rel_path), "%s/%s", relative_path, entry->d_name);
            }
            collect_files_from_dir(base_path, new_rel_path, files, count);
        }
        closedir(dir);
    } 
    else if (S_ISREG(st.st_mode)) {
        *files = realloc(*files, (*count + 1) * sizeof(file_entry_t));
        (*files)[*count].full_path = strdup(full_path);
        (*files)[*count].relative_path = strdup(relative_path);
        (*count)++;
    }
}

file_entry_t* collect_all_files(char **paths, int path_count, int *total_files) {
    file_entry_t *all_files = NULL;
    *total_files = 0;
    
    for (int i = 0; i < path_count; i++) {
        struct stat st;
        if (stat(paths[i], &st) != 0) {
            printf("Ошибка: файл/директория не существует: %s\n", paths[i]);
            continue;
        }
        
        if (S_ISDIR(st.st_mode)) {
            collect_files_from_dir(paths[i], "", &all_files, total_files);
        } else if (S_ISREG(st.st_mode)) {
            const char *filename = strrchr(paths[i], '/');
            filename = filename ? filename + 1 : paths[i];
            
            all_files = realloc(all_files, (*total_files + 1) * sizeof(file_entry_t));
            all_files[*total_files].full_path = strdup(paths[i]);
            all_files[*total_files].relative_path = strdup(filename);
            (*total_files)++;
        }
    }
    
    return all_files;
}

void run_sequential_mode(file_entry_t  *input_files, int num_files, FILE *log_file) {
    int success = 0, error = 0;
    for (int i = 0; i < num_files && keep_running; i++) {
        int result = append_file_to_container(input_files[i].full_path, input_files[i].relative_path);
        
        if (result == 0) {
            success++;
            printf("  + %s\n", input_files[i].relative_path);
            log_operation(log_file, &log_mutex, 0, input_files[i].relative_path, "УСПЕХ");
        } 
        else if (result == -2){
            printf("Ошибка: файл %s уже существует в образе\n", input_files[i].relative_path);
            log_operation(log_file, &log_mutex, 0, input_files[i].relative_path, "ОШИБКА");
        }
        else {
            error++;
            printf("  ! ОШИБКА: %s\n", input_files[i].relative_path);
            log_operation(log_file, &log_mutex, 0, input_files[i].relative_path, "ОШИБКА");
        }
    }
    printf("\nРезультат: %d успешно, %d ошибок\n", success, error);
}

void run_parallel_mode(file_entry_t *input_files, int num_files, FILE *log_file) {
    pthread_mutex_t file_mutex = PTHREAD_MUTEX_INITIALIZER;
    int current_file_index = 0;
    
    pthread_t workers[WORKERS_COUNT];
    thread_data_t thread_data[WORKERS_COUNT];
    
    for (int i = 0; i < WORKERS_COUNT; i++) {
        thread_data[i].input_files = input_files;
        thread_data[i].total_files = num_files;
        thread_data[i].current_file_index = &current_file_index;
        thread_data[i].running = &keep_running;
        thread_data[i].file_mutex = &file_mutex;
        thread_data[i].log_file = log_file;
        thread_data[i].log_mutex = &log_mutex;
        thread_data[i].thread_id = i + 1;
        
        if (pthread_create(&workers[i], NULL, file_processor_thread, &thread_data[i]) != 0) {
            printf("Ошибка создания потока %d\n", i + 1);
            keep_running = 0;
        }
    }
    
    for (int i = 0; i < WORKERS_COUNT; i++) {
        pthread_join(workers[i], NULL);
    }
    pthread_mutex_destroy(&file_mutex);
}

void signal_handler(int sig) {
    printf("\nПолучен сигнал SIGINT. Завершение работы...\n");

     if (log_file) {
        char timestamp[64];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(log_file, "[%s] SIGINT: Прерывание по клавиатуре\n", timestamp);
        fflush(log_file);
    }
    _exit(sig);
}

void segfault_handler(int sig) {
    interruption_received = sig;
    fprintf(stderr, "\nОШИБКА: Попытка чтения защищенной памяти (SIGSEGV)\n");
    if (log_file) {
        char timestamp[64];
        get_timestamp(timestamp, sizeof(timestamp));
        fprintf(log_file, "[%s] SIGSEGV: Попытка доступа к защищенной памяти\n", timestamp);
        fflush(log_file);
    }
    _exit(sig);
}

int main(int argc, char *argv[]) {
    signal(SIGSEGV, segfault_handler);
    signal(SIGINT, signal_handler);

    if (argc < 3) {
        printf("Использование:\n");
        printf("\tДобавление:  %s -add -image disk.img -key <ключ> <файлы|директория>\n", argv[0]);
        printf("\tСписок:      %s -list -image disk.img\n", argv[0]);
        printf("\tИзвлечение:  %s -get -image disk.img -key <ключ> -out <файл> <имя_в_образе>\n", argv[0]);
        return 1;
    }

    if (load_rc4_library() != 0) {
        return 1;
    }

    char *operation = argv[1];
    container_path = NULL;
    char *master_key = NULL;
    size_t master_key_len = 0;
    char *output_file = NULL;
    char *file_to_get = NULL;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-image") == 0 && i + 1 < argc) {
            container_path = argv[++i];
        }
        else if (strcmp(argv[i], "-key") == 0 && i + 1 < argc) {
            master_key = argv[++i];
            master_key_len = strlen(master_key);
        }
        else if (strcmp(argv[i], "-out") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        }
    }

    if (strcmp(operation, "-get") == 0) {
        for (int i = 2; i < argc; i++) {
            if (argv[i][0] != '-' && 
                strcmp(argv[i], container_path) != 0 &&
                master_key && strcmp(argv[i], master_key) != 0 &&
                output_file && strcmp(argv[i], output_file) != 0) {
                file_to_get = argv[i];
                break;
            }
        }
    }

    if (!container_path) {
        printf("Ошибка: не указан -image\n");
        return 1;
    }

    if (init_secure_key_storage() != 0) {
        printf("Ошибка инициализации защищенного хранилища ключа\n");
        return 1;
    }

    if (master_key && master_key_len > 0) {
        if (set_key(master_key, master_key_len) != 0) {
            printf("Ошибка установки ключа\n");
            cleanup_secure_key();
            return 1;
        }
        printf("Ключ установлен (длина: %zu байт)\n", master_key_len);
    } 
    else if (strcmp(operation, "-add") == 0 || strcmp(operation, "-get") == 0) {
        printf("Ошибка: для операций добавления и извлечения требуется ключ\n");
        cleanup_secure_key();
        return 1;
    }

    log_file = fopen("log.txt", "a");
    if (!log_file) {
        printf("Ошибка создания log.txt\n");
        cleanup_secure_key();
        return 1;
    }
    char timestamp[64];
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file, "\n=== Новая сессия %s ===\n", timestamp);

    if (strcmp(operation, "-add") == 0) {
        struct stat st;
        if (stat(container_path, &st) != 0) {
            int fd = open(container_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
            if (fd < 0) {
                printf("Ошибка создания образа\n");
                cleanup_secure_key();
                return 1;
            }
            close(fd);
            printf("Создан новый образ: %s\n", container_path);
        } 
        else {
            printf("Добавление в существующий образ: %s\n", container_path);
            fprintf(log_file, "Добавление в образ: %s\n", container_path);
        }
        
        int start_idx = 1;
        while (start_idx < argc && strcmp(argv[start_idx], "-add") != 0) start_idx++;
        start_idx++;
        while (start_idx < argc && (strcmp(argv[start_idx], "-image") == 0 || 
               strcmp(argv[start_idx], "-key") == 0 || strcmp(argv[start_idx], "-out") == 0)) {
            start_idx += 2;
        }
        
        if (start_idx >= argc) {
            printf("Ошибка: не указаны файлы для добавления\n");
            fclose(log_file);
            cleanup_secure_key();
            return 1;
        }
        
        int num_files = 0;
        file_entry_t *all_files = collect_all_files(&argv[start_idx], argc - start_idx, &num_files);

        if (num_files == 0) {
            printf("Нет файлов для добавления\n");
            fclose(log_file);
            cleanup_secure_key();
            return 1;
        }
        
        printf("\nНайдено файлов: %d\n", num_files);
        
        if (num_files < 5) {
            printf("\nРежим: ПОСЛЕДОВАТЕЛЬНЫЙ\n");
            fprintf(log_file, "Режим: ПОСЛЕДОВАТЕЛЬНЫЙ\n");
            run_sequential_mode(all_files, num_files, log_file);
        } else {
            printf("\nРежим: ПАРАЛЛЕЛЬНЫЙ (%d потоков)\n", WORKERS_COUNT);
            fprintf(log_file, "Режим: ПАРАЛЛЕЛЬНЫЙ (%d потоков)\n", WORKERS_COUNT);
            run_parallel_mode(all_files, num_files, log_file);
        }
        
        for (int i = 0; i < num_files; i++) {
            free(all_files[i].full_path);
            free(all_files[i].relative_path);
        }
        free(all_files);
    }
    else if (strcmp(operation, "-list") == 0) {
        list_files_in_container();
    }
    else if (strcmp(operation, "-get") == 0) {
        if (!container_path || !file_to_get || !output_file) {
            printf("Использование: %s -get -image disk.img -key <key> -out <файл> <имя_в_образе>\n", argv[0]);
            fclose(log_file);
            cleanup_secure_key();
            return 1;
        }
        extract_file_from_container(file_to_get, output_file);
    }
    else {
        printf("Неизвестная команда. Используйте -add, -list или -get\n");
    }
    
    cleanup_secure_key();
    get_timestamp(timestamp, sizeof(timestamp));
    fprintf(log_file, "=== Завершение %s ===\n\n", timestamp);
    fclose(log_file);

    return 0;
}