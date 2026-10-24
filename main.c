#include "minigit.h"

void print_usage() {
    printf("==================================================\n");
    printf(" Mini Version Control System (Git-like with Hashes)\n");
    printf("==================================================\n");
    printf("Usage:\n");
    printf("  ./minigit init                   - Create a new repository[cite: 1]\n");
    printf("  ./minigit add <file>             - Add project files[cite: 1]\n");
    printf("  ./minigit rm <file>              - Remove project files[cite: 1]\n");
    printf("  ./minigit commit <message>       - Save version with unique SHA-256 ID[cite: 1]\n");
    printf("  ./minigit log                    - Display version history[cite: 1]\n");
    printf("  ./minigit diff <v1> <v2> <file>  - Compare different versions of files[cite: 1]\n");
    printf("  ./minigit restore <version_id>   - Restore previously saved versions[cite: 1]\n");
    printf("  ./minigit search <keyword>       - Search version records[cite: 1]\n");
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        print_usage();
        return 1;
    }

    char *command = argv[1];

    if (strcmp(command, "init") == 0) {
        return init_repository();
    } else if (strcmp(command, "add") == 0 && argc == 3) {
        return add_file(argv[2]);
    } else if (strcmp(command, "rm") == 0 && argc == 3) {
        return remove_file(argv[2]);
    } else if (strcmp(command, "commit") == 0 && argc == 3) {
        return save_version(argv[2]);
    } else if (strcmp(command, "log") == 0) {
        return display_history();
    } else if (strcmp(command, "diff") == 0 && argc == 5) {
        return compare_versions(argv[2], argv[3], argv[4]);
    } else if (strcmp(command, "restore") == 0 && argc == 3) {
        return restore_version(argv[2]);
    } else if (strcmp(command, "search") == 0 && argc == 3) {
        return search_records(argv[2]);
    } else {
        printf("Invalid command or missing arguments.\n");
        print_usage();
        return 1;
    }
}