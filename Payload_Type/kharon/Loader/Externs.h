#include <windows.h>

#define KH_WINMAIN 0x100
#define KH_DLLMAIN 0x200
#define KH_SVCMAIN 0x300

#ifndef KH_MAIN
#define KH_MAIN 0
#endif

#if KH_MAIN == KH_DLLMAIN
#define DLLEXPORT __declspec(dllexport)
#else
#define DLLEXPORT
#endif