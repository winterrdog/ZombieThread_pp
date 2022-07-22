#ifndef DANGER_H
#define DANGER_H

#include <windows.h>
#include <chrono>
#include <iostream>
#include <tlhelp32.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))
#define HIT_EM_UP int main(void)

// function prototypes
DWORD FindProcessId(const char *processName, const size_t &procStrLen);

#endif
