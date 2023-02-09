//
// Created by Sora on 2023/2/8.
//

#include "println.h"
#include "stdio.h"

void println_str(char * message) {
    printf("%s\r\n", message);
}

void println_int(unsigned int number) {
    printf("%d\r\n", number);
}