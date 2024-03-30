#include <stdio.h>

int bssVar;

int dataVar = 0xDA7A;

const int rodataVar = 0xC0D474;

void bss_init(int bss) {
    bssVar = 0xB55DA7A;
}

int main() {
    int stackVar = 5;
    bss_init(bssVar);
    printf("%x %x %x %x", dataVar, rodataVar, bssVar, stackVar);
    return 0;
}