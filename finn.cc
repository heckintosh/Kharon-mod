#include <windows.h>
#include <stdio.h>

typedef struct {
    ULONG N1;
    ULONG N2;
} STRUCT_1;

int main() {
    STRUCT_1** StrList = (STRUCT_1**)malloc( sizeof( STRUCT_1 ) * 4 );
}