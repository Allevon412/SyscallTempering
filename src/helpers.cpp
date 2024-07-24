//
// Created by Brendan Ortiz on 7/23/2024.
//

#include "../include/helpers.h"

void MemoryCopy(void* dest, const void* src, size_t n) {
    char* csrc = (char*)src;
    char* cdest = (char*)dest;

    // Copying data byte by byte
    for (size_t i = 0; i < n; i++)
        cdest[i] = csrc[i];
}

unsigned long int n = 1;
// Seed the generator
void int_srand(unsigned int seed) {
    n = seed;
}

// Generate a random number
int int_rand() {
    n = n * 1103515245 + 12345;
    return (unsigned int)(n/65536) % 32768;
}