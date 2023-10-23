#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <target_host>\n", argv[0]);
        return 1;
    }

    char command[512];
    snprintf(command, sizeof(command), "sslscan %s", argv[1]);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("Error opening pipe");
        return 1;
    }

    char buffer[1024];
    size_t n;

    while ((n = fread(buffer, 1, sizeof(buffer) - 1, fp)) > 0) {
        buffer[n] = '\0';
        printf("%s", buffer);
    }

    int status = pclose(fp);
    if (WIFEXITED(status)) {
        if (WEXITSTATUS(status) == 0) {
            return 0;  // Success
        } else {
            fprintf(stderr, "Error running sslscan. Exit code: %d\n", WEXITSTATUS(status));
            return 1;
        }
    } else {
        fprintf(stderr, "Error: sslscan did not exit properly\n");
        return 1;
    }
}
