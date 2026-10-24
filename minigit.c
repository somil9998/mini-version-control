#include "minigit.h"

/* --- Self-Contained SHA-256 Implementation --- */
typedef struct {
    uint8_t data[64];
    uint32_t datalen;
    unsigned long long bitlen;
    uint32_t state[8];
} SHA256_CTX;

#define ROTRIGHT(a,b) (((a) >> (b)) | ((a) << (32-(b))))
#define CH(x,y,z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x,2) ^ ROTRIGHT(x,13) ^ ROTRIGHT(x,22))
#define EP1(x) (ROTRIGHT(x,6) ^ ROTRIGHT(x,11) ^ ROTRIGHT(x,25))
#define SIG0(x) (ROTRIGHT(x,7) ^ ROTRIGHT(x,18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x,17) ^ ROTRIGHT(x,19) ^ ((x) >> 10))

static const uint32_t k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(SHA256_CTX *ctx, const uint8_t data[]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for ( ; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }
    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(SHA256_CTX *ctx) {
    ctx->datalen = 0; ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
}

static void sha256_update(SHA256_CTX *ctx, const uint8_t data[], size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(SHA256_CTX *ctx, uint8_t hash[]) {
    uint32_t i = ctx->datalen;
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }
    ctx->bitlen += (ctx->datalen * 8);
    ctx->data[63] = ctx->bitlen;
    ctx->data[62] = ctx->bitlen >> 8;
    ctx->data[61] = ctx->bitlen >> 16;
    ctx->data[60] = ctx->bitlen >> 24;
    ctx->data[59] = ctx->bitlen >> 32;
    ctx->data[58] = ctx->bitlen >> 40;
    ctx->data[57] = ctx->bitlen >> 48;
    ctx->data[56] = ctx->bitlen >> 56;
    sha256_transform(ctx, ctx->data);
    for (i = 0; i < 4; ++i) {
        hash[i]      = (ctx->state[0] >> (24 - i * 8));
        hash[i + 4]  = (ctx->state[1] >> (24 - i * 8));
        hash[i + 8]  = (ctx->state[2] >> (24 - i * 8));
        hash[i + 12] = (ctx->state[3] >> (24 - i * 8));
        hash[i + 16] = (ctx->state[4] >> (24 - i * 8));
        hash[i + 20] = (ctx->state[5] >> (24 - i * 8));
        hash[i + 24] = (ctx->state[6] >> (24 - i * 8));
        hash[i + 28] = (ctx->state[7] >> (24 - i * 8));
    }
}

void compute_sha256(const uint8_t *data, size_t len, char output_buffer[65]) {
    uint8_t hash[32];
    SHA256_CTX ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++) {
        sprintf(output_buffer + (i * 2), "%02x", hash[i]);
    }
    output_buffer[64] = 0;
}
/* -------------------------------------------------------------------------- */

void copy_file(const char *src, const char *dest) {
    FILE *s = fopen(src, "rb");
    FILE *d = fopen(dest, "wb");
    if (!s || !d) {
        if (s) fclose(s);
        if (d) fclose(d);
        return;
    }
    char buffer[1024];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), s)) > 0) {
        fwrite(buffer, 1, bytes, d);
    }
    fclose(s);
    fclose(d);
}

int init_repository(void) {
    struct stat st = {0};
    if (stat(".minigit", &st) == 0) {
        printf("Error: Repository already exists[cite: 1].\n");
        return 1;
    }

    if (SAFE_MKDIR(".minigit") != 0 ||
        SAFE_MKDIR(".minigit/commits") != 0 ||
        SAFE_MKDIR(".minigit/staging") != 0) {
        printf("Error: Failed to create repository directories.\n");
        return 1;
    }
    
    FILE *f = fopen(".minigit/staging/tracked_list", "w");
    if (f) fclose(f);

    printf("Initialized empty MiniGit repository in .minigit/\n");
    return 0;
}

int add_file(const char *filename) {
    struct stat buffer;
    if (stat(filename, &buffer) != 0) {
        printf("Error: File '%s' does not exist in working directory.\n", filename);
        return 1;
    }

    FILE *f = fopen(".minigit/staging/tracked_list", "r");
    char line[MAX_PATH];
    if (f) {
        while (fgets(line, sizeof(line), f)) {
            line[strcspn(line, "\r\n")] = 0;
            if (strcmp(line, filename) == 0) {
                fclose(f);
                printf("File '%s' is already being tracked[cite: 1].\n", filename);
                return 0;
            }
        }
        fclose(f);
    }

    f = fopen(".minigit/staging/tracked_list", "a");
    if (!f) {
        printf("Error: Not a minigit repository. Run 'init' first[cite: 1].\n");
        return 1;
    }
    fprintf(f, "%s\n", filename);
    fclose(f);
    printf("File '%s' added to tracking staging area[cite: 1].\n", filename);
    return 0;
}

int remove_file(const char *filename) {
    FILE *f = fopen(".minigit/staging/tracked_list", "r");
    if (!f) {
        printf("Error: Not a minigit repository[cite: 1].\n");
        return 1;
    }

    FILE *temp = fopen(".minigit/staging/temp_list", "w");
    char line[MAX_PATH];
    int found = 0;

    while (fgets(line, sizeof(line), f)) {
        char clean_name[MAX_PATH];
        sscanf(line, "%s", clean_name);
        if (strcmp(clean_name, filename) == 0) {
            found = 1;
        } else {
            fprintf(temp, "%s", line);
        }
    }
    fclose(f);
    fclose(temp);

    remove(".minigit/staging/tracked_list");
    rename(".minigit/staging/temp_list", ".minigit/staging/tracked_list");

    if (found) {
        printf("File '%s' removed from tracking[cite: 1].\n", filename);
        return 0;
    } else {
        printf("File '%s' was not found in tracked list.\n", filename);
        return 1;
    }
}

int save_version(const char *message) {
    char raw_data[MAX_LINE + 100];
    snprintf(raw_data, sizeof(raw_data), "%s-%ld", message, (long)time(NULL));

    char version_id[65];
    compute_sha256((uint8_t *)raw_data, strlen(raw_data), version_id);

    char commit_dir[MAX_PATH];
    sprintf(commit_dir, ".minigit/commits/%s", version_id);

    if (SAFE_MKDIR(commit_dir) != 0) {
        printf("Error creating commit snapshot directory.\n");
        return 1;
    }

    char files_dir[MAX_PATH];
    sprintf(files_dir, "%s/files", commit_dir);
    SAFE_MKDIR(files_dir);

    char meta_path[MAX_PATH];
    sprintf(meta_path, "%s/metadata", commit_dir);
    FILE *meta_f = fopen(meta_path, "w");
    if (meta_f) {
        fprintf(meta_f, "Commit Hash: %s\nMessage: %s\n", version_id, message);
        fclose(meta_f);
    }

    FILE *list_f = fopen(".minigit/staging/tracked_list", "r");
    if (!list_f) {
        printf("Error reading tracked files list.\n");
        return 1;
    }

    char filename[MAX_PATH];
    while (fscanf(list_f, "%s", filename) == 1) {
        char dest_path[MAX_PATH];
        sprintf(dest_path, "%s/%s", files_dir, filename);
        copy_file(filename, dest_path);
    }
    fclose(list_f);

    printf("Successfully saved version[cite: 1]. SHA-256 Hash ID: %s\n", version_id);
    return 0;
}

int display_history(void) {
    DIR *dir = opendir(".minigit/commits");
    if (!dir) {
        printf("Error: No version history found[cite: 1].\n");
        return 1;
    }

    printf("\n--- Version History Log[cite: 1] ---\n");
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char meta_path[MAX_PATH];
            sprintf(meta_path, ".minigit/commits/%s/metadata", entry->d_name);
            FILE *f = fopen(meta_path, "r");
            if (f) {
                char line[MAX_LINE];
                printf("----------------------------------------\n");
                while (fgets(line, sizeof(line), f)) {
                    printf("%s", line);
                }
                fclose(f);
            }
        }
    }
    printf("----------------------------------------\n");
    closedir(dir);
    return 0;
}

int compare_versions(const char *v1, const char *v2, const char *filename) {
    char path1[MAX_PATH], path2[MAX_PATH];
    sprintf(path1, ".minigit/commits/%s/files/%s", v1, filename);
    sprintf(path2, ".minigit/commits/%s/files/%s", v2, filename);

    FILE *f1 = fopen(path1, "r");
    FILE *f2 = fopen(path2, "r");

    if (!f1 || !f2) {
        if (f1) fclose(f1);
        if (f2) fclose(f2);
        printf("Error: File or version hashes could not be found for comparison[cite: 1].\n");
        return 1;
    }

    printf("\nComparing '%s' between version %s and %s[cite: 1]:\n", filename, v1, v2);
    printf("--- Version %s\n+++ Version %s\n", v1, v2);

    char line1[MAX_LINE], line2[MAX_LINE];
    int line_num = 1;
    int eof1 = 0, eof2 = 0;

    while (!eof1 || !eof2) {
        char *r1 = fgets(line1, sizeof(line1), f1);
        char *r2 = fgets(line2, sizeof(line2), f2);
        eof1 = (r1 == NULL);
        eof2 = (r2 == NULL);

        if (!eof1 && !eof2) {
            if (strcmp(line1, line2) != 0) {
                printf("Line %d:\n< %s> %s", line_num, line1, line2);
            }
        } else if (!eof1) {
            printf("Line %d (Removed in v%s):\n< %s", line_num, v2, line1);
        } else if (!eof2) {
            printf("Line %d (Added in v%s):\n> %s", line_num, v2, line2);
        }
        line_num++;
    }

    fclose(f1);
    fclose(f2);
    return 0;
}

int restore_version(const char *version_id) {
    char files_dir[MAX_PATH];
    sprintf(files_dir, ".minigit/commits/%s/files", version_id);

    DIR *dir = opendir(files_dir);
    if (!dir) {
        printf("Error: Version hash ID '%s' not found[cite: 1].\n", version_id);
        return 1;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_REG) {
            char src_path[MAX_PATH], dest_path[MAX_PATH];
            sprintf(src_path, "%s/%s", files_dir, entry->d_name);
            sprintf(dest_path, "%s", entry->d_name);
            copy_file(src_path, dest_path);
            printf("Restored file: %s[cite: 1]\n", entry->d_name);
        }
    }
    closedir(dir);
    printf("Successfully restored project to version hash ID: %s[cite: 1]\n", version_id);
    return 0;
}

int search_records(const char *keyword) {
    DIR *dir = opendir(".minigit/commits");
    if (!dir) {
        printf("Error: No version history available to search[cite: 1].\n");
        return 1;
    }

    printf("\nSearch Results for keyword '%s'[cite: 1]:\n", keyword);
    struct dirent *entry;
    int found_count = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR && strcmp(entry->d_name, ".") != 0 && strcmp(entry->d_name, "..") != 0) {
            char meta_path[MAX_PATH];
            sprintf(meta_path, ".minigit/commits/%s/metadata", entry->d_name);
            FILE *f = fopen(meta_path, "r");
            if (f) {
                char line[MAX_LINE];
                int match = 0;
                char record_buffer[MAX_LINE * 2] = "";
                while (fgets(line, sizeof(line), f)) {
                    strcat(record_buffer, line);
                    if (strstr(line, keyword) != NULL) {
                        match = 1;
                    }
                }
                fclose(f);
                if (match) {
                    printf("----------------------------------------\n%s", record_buffer);
                    found_count++;
                }
            }
        }
    }
    printf("----------------------------------------\n");
    printf("Found %d matching version record(s)[cite: 1].\n", found_count);
    closedir(dir);
    return 0;
}