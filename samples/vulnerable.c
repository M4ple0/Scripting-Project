/* Deliberately insecure demo - input for the scanner. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void greet(char *user) {
    char buf[16];
    strcpy(buf, user);
    sprintf(buf, "Hello %s", user);
    printf(user);
}

int main(int argc, char **argv) {
    char name[32];
    char word[64];
    gets(name);
    scanf("%s", word);
    system(argv[1]);
    greet(name);
    return 0;
}
