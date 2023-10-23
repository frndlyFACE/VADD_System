#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char *argv[]) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <target_host> <port_range>\n", argv[0]);
        return 1;
    }

    char nmapCommand[512];
    snprintf(nmapCommand, sizeof(nmapCommand), "nmap -p %s -sV -A -T4 --min-rate 500 --script vuln %s", argv[2], argv[1]);

    char sedCommand[] = "sed 's/Nmap/VADD/g'"; // Replace Nmap with VADD

    // Combine nmap and sed commands
    char combinedCommand[1024];
    snprintf(combinedCommand, sizeof(combinedCommand), "%s | %s", nmapCommand, sedCommand);

    FILE *fp = popen(combinedCommand, "r");
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
            fprintf(stderr, "Error running Nmap. Exit code: %d\n", WEXITSTATUS(status));
            return 1;
        }
    } else {
        fprintf(stderr, "Error: Nmap did not exit properly\n");
        return 1;
    }
}
