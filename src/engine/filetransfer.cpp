#include "../net/sock.h" // before windows.h !!!

#include <string>

#include "filetransfer.h"

#include "../dbg.h"
#include "../values.h"
#include "../schannel/TlsSock.h"
#include "../files/Files.h"
#include "MessageHandler.h"
#include "../gui/StringPool.h"

#ifdef GUI
extern HINSTANCE MainInstance;
extern HWND MainWindow;
INT_PTR CALLBACK FTAcceptDialog(HWND, UINT, WPARAM, LPARAM);
#endif



void initFTObject(
    _Out_ PFT_OBJECTS obj
)
{
    ZeroMemory(obj, sizeof(*obj));
    obj->Socket = INVALID_SOCKET;
}

void showSentFileInfo(
    _In_ const char* label,
    _In_opt_ uint8_t* sha256,
    _In_ size_t size,
    _In_ const char* base_name,
    _In_ size_t base_name_ln,
    _In_ const char* name,
    _In_ bool self
)
{
    char sHash[SHA256_STRING_BUFFER_LN];
    if ( sha256 != NULL )
        hashToString(sha256, SHA256_BYTES_LN, sHash, SHA256_STRING_BUFFER_LN);
    
    size_t msgd_ln = 52 + SHA256_STRING_LN + base_name_ln + (2*strlen(label));
    size_t smsg_size = sizeof(SCHAT_MESSAGE_HEADER) + msgd_ln;
    
    uint8_t* msgb = new uint8_t[smsg_size];
    PSCHAT_MESSAGE_HEADER smsg = (PSCHAT_MESSAGE_HEADER)msgb;

    strcpy_s(smsg->name, MAX_NAME_LN, name);
    smsg->name[MAX_NAME_LN-1] = 0;
    smsg->data_ln = (uint32_t)msgd_ln;
    char* msgd = smsg->data;
    if ( sha256 != NULL )
        sprintf_s(msgd, msgd_ln, "[%s]\r\nfile: %s\r\nsize: 0x%zx\r\nhash: %s\r\n[\\%s]\r\n", label, base_name, size, sHash, label); 
    else
        sprintf_s(msgd, msgd_ln, "[%s]\r\nfile: %s\r\n[\\%s]\r\n", label, base_name, label); 

    showMessages(smsg, self);
    delete[] msgb;
}

void sendReceivedFileInfo(
    _In_ bool success,
    _In_ const char* path, 
    _In_ const char* label,
    _In_ const char* name,
    _In_ bool self,
    _In_ SOCKET Socket,
    _In_ PCtxtHandle phContext,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
)
{
    uint8_t hash[SHA256_BYTES_LN];
    char sHash[SHA256_STRING_BUFFER_LN];
    if ( success )
    {
        int s = sha256File(path, hash, SHA256_BYTES_LN);
        if ( s != 0 )
        {
            logger.logError(loggerId, s, "Calculating hash failed!\n");
            showInfoStatus("ERROR: Calculating hash failed!\n");
            return;
        }
        hashToString(hash, SHA256_BYTES_LN, sHash, SHA256_STRING_BUFFER_LN);
    }

    const char* base_name = NULL;
    size_t base_name_ln = getBaseName(path, strlen(path), &base_name);

    size_t msgd_ln = 24+SHA256_STRING_BUFFER_LN + base_name_ln + (2*strlen(label));
    size_t msgb_size = sizeof(SCHAT_MESSAGE_HEADER)+msgd_ln;
    
    PSCHAT_MESSAGE_HEADER message = (PSCHAT_MESSAGE_HEADER)(pbIoBuffer + pSizes->cbHeader);
    ZeroMemory(message, msgb_size);
    message->bh.size = msgb_size;
    message->bh.type = MSG_TYPE_TEXT;
    message->bh.flags = MSG_FLAG_STOP;
    strcpy_s(message->name, MAX_NAME_LN, name);
    message->name[MAX_NAME_LN-1] = 0;
    message->data_ln = (uint32_t)msgd_ln;
    char* msgd = message->data;
    if ( success )
        sprintf_s(msgd, msgd_ln, "[%s]\r\nfile: %s\r\nhash: %s\r\n[\\%s]", label, base_name, sHash, label); 
    else
        sprintf_s(msgd, msgd_ln, "[%s]\r\nfile: %s\r\n[\\%s]", label, base_name, label); 

    showMessages(message, self);

    // showMessages(msg, TRUE);
    int n = sendSChannelData(
        (PUCHAR)message, 
        (ULONG)message->bh.size, 
        Socket, 
        phContext,
        pSizes,
        pbIoBuffer,
        cbIoBuffer
    );
    if ( n != 0 )
    {
        logger.logError(loggerId, n, "error sending data\n");
        //showInfoStatus("error sending data");
    }
}

int sendAcceptedFileInfo(
    _In_ bool accepted,
    _In_ const char* name,
    _In_ const char* path,
    _In_ size_t path_ln,
    _In_ SOCKET Socket,
    _In_ PCtxtHandle phContext,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ PBYTE pbIoBuffer,
    _In_ ULONG cbIoBuffer
)
{
    int s = 0;
    
    const char* base_name = NULL;
    size_t base_name_ln = getBaseName(path, path_ln, &base_name);

    size_t msgb_size = sizeof(SCHAT_FILE_STATUS_HEADER) + base_name_ln;
    ULONG flag = accepted ? MSG_FLAG_ACCEPT : MSG_FLAG_CANCEL;

    PSCHAT_FILE_STATUS_HEADER message = (PSCHAT_FILE_STATUS_HEADER)(pbIoBuffer + pSizes->cbHeader);
    ZeroMemory(message, msgb_size);
    message->bh.size = msgb_size;
    message->bh.type = MSG_TYPE_FT_STATUS;
    message->bh.flags = MSG_FLAG_STOP | flag;
    message->base_name_ln = (uint32_t)base_name_ln;
    memcpy(message->base_name, base_name, base_name_ln); // strcpy_s aborts due to wrong checks
    message->base_name[base_name_ln] = 0;
    strcpy_s(message->name, MAX_NAME_LN, name);
    message->name[MAX_NAME_LN-1] = 0;

    if ( !accepted )
    {
        showSentFileInfo(
            FT_INFO_LABEL_CANCELED,
            NULL,
            0,
            base_name,
            base_name_ln,
            name,
            true
        );
    }

    s = sendSChannelData(
            (PUCHAR)message, 
            (ULONG)message->bh.size, 
            Socket, 
            phContext,
            pSizes,
            pbIoBuffer,
            cbIoBuffer
        );
    if ( s != 0 )
    {
        logger.logError(loggerId, s, "error sending data\n");
        //showInfoStatus("error sending data");
    }

    return s;
}

int saveFile(
    _In_ PFILE_TRANSFER_DATA ftd, 
    _In_ uint8_t* buffer, 
    _In_ size_t buffer_ln
)
{
    int s = 0;
    
    size_t bWritten = fwrite(buffer, 1, buffer_ln, ftd->file);
    if ( bWritten != buffer_ln )
    {
        s = SCHAT_ERROR_WRITE_FILE;
        logger.logError(loggerId, s, "writing file failed\n");
        return s;
    }
    ftd->written += bWritten;
    
    if ( ftd->written >= ftd->size )
    {
        fclose(ftd->file);
        ftd->file = NULL;
    }

    return s;
}

ULONG WINAPI recvFTDataThread(
    LPVOID lpParam
)
{
    int s = 0;
    int answer = IDNO;
    PFT_RECEIVE_THREAD_DATA rtd = (PFT_RECEIVE_THREAD_DATA)(lpParam);

    uint8_t other_ft_cert_hash[SHA256_BYTES_LN];
    
    const char* base_name = NULL;
    size_t base_name_ln = 0;
    const char* fmt_str = "Accept file transfer?\r\nFile: %s";
    size_t msg_ln = 0;
    char* msg = NULL;
    
    SOCKADDR_STORAGE raddr;
    socklen_t raddr_ln;

    s = allocateBuffer(rtd->Sizes, &rtd->pbIoBuffer, &rtd->cbIoBuffer);
    if ( s != 0 )
    {
        logger.logError(loggerId, s, "allocate send file buffer failed!\n");
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }

    ZeroMemory(other_ft_cert_hash, SHA256_BYTES_LN);

    // accept new ft socket connection
    if ( rtd->type == ENGINE_TYPE_SERVER )
    {
        // accept blocking receive thread
        s = acceptTLSSocket(
                ListenSocket, 
                &rtd->Socket, 
                &rtd->Context, 
                &hServerCreds, 
                rtd->pbIoBuffer, 
                rtd->cbIoBuffer,
                other_ft_cert_hash,
                &raddr,
                &raddr_ln
            );
        if ( s != 0 )
            goto clean;
#ifdef DEBUG_PRINT
        logger.logInfo(loggerId, 0, "FT accepted\n");
#endif
    }
    // or connect to an accepting socket
    else if ( rtd->type == ENGINE_TYPE_CLIENT )
    {
        s = connectTLSSocket(
                target_ip, 
                target_port, 
                family, 
                &rtd->Socket, 
                &rtd->Context, 
                &hClientCreds,
                other_ft_cert_hash
            );
        if ( s != 0 )
        {
            goto clean;
        }
#ifdef DEBUG_PRINT
        logger.logInfo(loggerId, 0, "FT Connected\n");
#endif
    }

    // compare ft certificate hash to main connection certificate
    if ( memcmp(other_cert_hash, other_ft_cert_hash, SHA256_BYTES_LN) != 0 )
    {
        s = SCHAT_ERROR_FT_CERT_MISSMATCH;
        logger.logError(loggerId, s, "SCHAT_ERROR_FT_CERT_MISSMATCH\n");
        goto clean;
    }

    //
    // msg box : accept file ?

    base_name_ln = getBaseName(rtd->ftd->path, rtd->ftd->path_ln, &base_name);
    fmt_str = "File: %s";
    msg_ln = strlen(fmt_str) + base_name_ln;
    msg = new char[msg_ln];
    sprintf_s(msg, msg_ln, fmt_str, base_name);
    MessageBeep(MB_ICONEXCLAMATION);

    answer = (INT) DialogBoxParamA(
                MainInstance, 
                MAKEINTRESOURCEA(IDD_ACCEPT_FT_DLG), 
                MainWindow, 
                FTAcceptDialog, 
                (LPARAM)msg
            );

    s = sendAcceptedFileInfo(
        answer == IDYES,
        rtd->name,
        rtd->ftd->path,
        rtd->ftd->path_ln,
        rtd->Socket,
        &rtd->Context,
        rtd->Sizes,
        rtd->pbIoBuffer,
        rtd->cbIoBuffer
    );
    
    if ( answer != IDYES || s != 0 )
    {
        showInfoStatus(SC_IS_FT_REJECTED);
        s = SCHAT_ERROR_FT_NOT_ACCEPTED;
        goto clean;
    }
    showInfoStatus(SC_IS_FT_ACCEPTED);


    //
    // enter receiving loop
    //

    togglePBar(TRUE);
    toggleFileBtn(FILE_TRANSFER_STATUS::ACTIVE);

    *(rtd->running) = TRUE;
    s = receiveSChannelData(
            rtd->Socket, 
            &hClientCreds, 
            &rtd->Context, 
            rtd->Sizes, 
            rtd->pbIoBuffer, 
            rtd->cbIoBuffer, 
            rtd->type,
            rtd->running
        );
    if ( s != 0 )
        goto clean;

clean:
    // If error, clean up here,
    // because the receive loop may never has been entered and the normal MessageHandler cleanup will not be reached.
    if ( s != 0 )
        cleanFileReceive(false);

    return s;
}

int disconnectFTRecvSocket(
    _Inout_ SOCKET* Socket,
    _Inout_ PCtxtHandle Context,
    _In_ PCredHandle Creds,
    _In_ INT type
)
{
    int s = 0;
#ifdef DEBUG_PRINT
        logger.logInfo(loggerId, 0, "disconnectFTRecvSocket\n");
#endif
        
    //(Creds);(type);(Socket);
    s = Disconnect(Socket, Creds, Context, type);
    
    if ( s == SEC_E_OK )
    {
        logger.logInfo(loggerId, 0, "SUCCESS: FT Socket terminated\n");
    }
    else
    {
        logger.logError(loggerId, s, "Disconnecting from server\n");
    }
    
    // Free SSPI context handle.
    if ( Context->dwLower != 0 && Context->dwUpper != 0)
    {
        g_pSSPI->DeleteSecurityContext(Context);
        Context->dwLower = 0;
        Context->dwUpper = 0;
    }

    showInfoStatus(SC_IS_FT_FINISHED);

    return s;
}
