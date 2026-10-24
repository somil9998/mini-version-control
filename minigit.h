#ifndef MINIGIT_H
#define MINIGIT_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <dirent.h>
#include <stdint.h>

// Prevent redefinition warning if stdlib.h already defines MAX_PATH
#ifndef MAX_PATH
#define MAX_PATH 260
#endif

#define MAX_LINE 1024

// Windows compatibility macro for mkdir (Windows mkdir only takes 1 argument)
#ifdef _WIN32
#include <direct.h>
#define SAFE_MKDIR(path) _mkdir(path)
#else
#define SAFE_MKDIR(path) mkdir(path, 0700)
#endif

// Functional requirements prototypes
int init_repository(void);
int add_file(const char *filename);
int remove_file(const char *filename);
int save_version(const char *message);
int display_history(void);
int compare_versions(const char *v1, const char *v2, const char *filename);
int restore_version(const char *version_id);
int search_records(const char *keyword);
void print_usage(void);

// Utility prototypes
void copy_file(const char *src, const char *dest);
void compute_sha256(const uint8_t *data, size_t len, char output_buffer[65]);

#endif