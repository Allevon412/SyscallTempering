//
// Created by Brendan Ortiz on 7/23/2024.
//

#ifndef HELPERS_H
#define HELPERS_H

#include <Windows.h>



void int_srand(unsigned int seed);
int int_rand();
void MemoryCopy(void* dest, const void* src, size_t n);

#endif //HELPERS_H
