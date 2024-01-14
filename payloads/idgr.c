#include <unistd.h>
#include <stdio.h>

int main() {
    char *bin = "/bin/bash";
    char *args[] = {bin, "-c",
                    "groups && id && hostname", "", NULL};
    char *const env[] = {NULL};
    execve(bin, args, env);
}