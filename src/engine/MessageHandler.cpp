#include <strsafe.h>

#include "../net/sock.h"
#include "../schannel/sec.h"

#include <mutex>

#include "MessageHandler.h"

#include "../dbg.h"
#include "../schannel/TlsSock.h"
#include "../files/Files.h"




static int handleTextMessage(
    _In_ PVOID data,
    _In_ ULONG dataSize
);

static int handleFTStatusMessage(
    _In_ PVOID data,
    _In_ ULONG dataSize
);

static int handleFileInfoMessage(
    _In_ PVOID data,
    _In_ ULONG dataSize,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ INT type
);

static int handleFileDataMessage(
    _In_ PVOID data, 
    _In_ ULONG dataSize,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _Out_ bool* ft_finished
);



static PFILE_TRANSFER_DATA ftd = NULL;
static PFT_RECEIVE_THREAD_DATA rtd = NULL;
static std::mutex mtx;



int handleMessage(
    _In_ PVOID data, 
    _In_ ULONG dataSize,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ ULONG type,
    _Inout_ BOOL* running
)
{
    int s = 0;
    PSCHAT_BASE_HEADER bh = (PSCHAT_BASE_HEADER)data;
    bool ft_finished = false;

#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "handleMessage %.*s:\n", 8, (CHAR*)&bh->type);
#endif

    if ( dataSize < sizeof(SCHAT_BASE_HEADER) || dataSize < bh->size )
    {
        logger.logInfo(loggerId, 0, "received corrupted message:\n");
        PrintHexDump(dataSize, data);
        showInfoStatus("Corrupted data");

        *running = FALSE;
        s = SCHAT_ERROR_CORRUPTED_DATA;
        goto clean;
    }

    // stop the receiving loop
    if ( bh->flags & MSG_FLAG_STOP )
    {
        *running = FALSE;
    }
    
    if ( bh->type == MSG_TYPE_TEXT )
    {
        s = handleTextMessage(
                data, 
                dataSize
            );
    }
    else if ( bh->type == MSG_TYPE_FT_STATUS )
    {
        s = handleFTStatusMessage(
                data, 
                dataSize
            );
    }
    else if ( bh->type == MSG_TYPE_FILE_INFO )
    {
        s = handleFileInfoMessage(
                data, 
                dataSize,
                pSizes,
                type
            );
    }
    else if ( bh->type == MSG_TYPE_FILE_DATA )
    {
        s = handleFileDataMessage(
                data, 
                dataSize,
                pSizes,
                &ft_finished
            );
    }
    else 
    {
        logger.logInfo(loggerId, 0, "Received unknown msg type:\n");
        PrintHexDump(dataSize, data);
        showInfoStatus("Unknown data");
        *running = FALSE;
        s = SCHAT_ERROR_UNKNOWN_DATA;
        goto clean;
    }

clean:
    if ( s != 0 || ft_finished )
    {
        if ( s != SCHAT_ERROR_MAX_FT )
        {
            cleanFileReceive(ft_finished);
        }
    }

    return s;
}

int handleTextMessage(
    _In_ PVOID data,
    _In_ ULONG dataSize
)
{
    int s = 0;

#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "MSG_TYPE_TEXT:\n");
#endif
    PSCHAT_MESSAGE_HEADER message = (PSCHAT_MESSAGE_HEADER)data;
    message->name[MAX_NAME_LN-1] = 0;
    //message->data_ln = strlen(message->data)+1;
    ((CHAR*)data)[dataSize-1] = 0;
#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "%s : %s\n", message->name, message->data);
#endif
    showMessages(message, FALSE);

    return s;
}

int handleFTStatusMessage(
    _In_ PVOID data,
    _In_ ULONG dataSize
)
{
    int s = 0;

    UNREFERENCED_PARAMETER(dataSize);

#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "MSG_TYPE_FT_STATUS:\n");
#endif
    PSCHAT_FILE_STATUS_HEADER message = (PSCHAT_FILE_STATUS_HEADER)data;
    
    // fills other name for sender side
    StringCchPrintfA(other_name, MAX_NAME_LN, message->name);
    other_name[MAX_NAME_LN-1] = 0;

    if ( message->bh.flags & MSG_FLAG_CANCEL )
    {
        showSentFileInfo(
            FT_INFO_LABEL_CANCELED,
            NULL,
            0,
            message->base_name,
            message->base_name_ln,
            message->name,
            false
        );
        return SCHAT_ERROR_FT_NOT_ACCEPTED;
    }
    else if ( message->bh.flags & MSG_FLAG_ACCEPT )
    {
        return 0;
    }
    else 
        return s;
}

int handleFileInfoMessage(
    _In_ PVOID data,
    _In_ ULONG dataSize,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _In_ INT type
)
{
    FILE* file = NULL;
    int s = 0;
    size_t path_ln;
    char* path = NULL;

    mtx.lock();
    if ( ft_send_obj.flags&FT_FLAG_ACTIVE || ft_recv_obj.flags&FT_FLAG_ACTIVE )
    {
        mtx.unlock();
        return SCHAT_ERROR_MAX_FT;
    }
    initFTObject(&ft_recv_obj);
    ft_recv_obj.flags |= FT_FLAG_ACTIVE;
    mtx.unlock();

#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "MSG_TYPE_FILE_INFO:\n");
#endif
    PSCHAT_FILE_INFO_HEADER info = (PSCHAT_FILE_INFO_HEADER)data;
    info->name[MAX_NAME_LN-1] = 0;
    info->base_name[info->base_name_ln] = 0;
    ((CHAR*)data)[dataSize-1] = 0;
       
#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "file_size: 0x%zx\nbase_name: %s (0x%x)\n", info->file_size, info->base_name, info->base_name_ln);
    logger.logInfo(loggerId, 0, "hash: ");
    printBytes(info->sha256, SHA256_BYTES_LN, 0, "");
#endif

    if ( info->file_size == 0 )
    {
        s = SCHAT_ERROR_FILE_SIZE;
        logger.logError(loggerId, s, "File size is 0.\n");
        goto clean;
    }

    path_ln = strlen(file_dir) + info->base_name_ln + 2; // separator and terminating 0
    
    ftd = (PFILE_TRANSFER_DATA)malloc(sizeof(FILE_TRANSFER_DATA) + path_ln);

    if ( ftd == NULL )
    {
        logger.logError(loggerId,  GetLastError(), "malloc FILE_TRANSFER_DATA failed\n");
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }

    // construct path
    path = ftd->path;
    if ( path == NULL )
    {
        logger.logError(loggerId, GetLastError(), "malloc path failed\n");
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }
    StringCchPrintfA(path, path_ln, "%s\\%s", ((file_dir==NULL)?".":file_dir), info->base_name);
    path[path_ln-1] = 0;
    ftd->path_ln = path_ln;
    strcpy_s(ftd->name, MAX_NAME_LN, info->name);
    ftd->name[MAX_NAME_LN-1] = 0;

#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "file path: %s\n", path);
#endif

    // open FILE*
    s = fopen_s(&file, path, "wb");
    if ( s != 0 )
    {
        logger.logError(loggerId, GetLastError(), "open transfer file failed\n");
        s = SCHAT_ERROR_OPEN_FILE;
        goto clean;
    }

    // fill transfer struct
    ftd->file = file;
    ftd->size = info->file_size;
    ftd->written = 0;
    
    // fills other name for receiver side
    strcpy_s(other_name, MAX_NAME_LN, info->name);
    other_name[MAX_NAME_LN-1] = 0;

#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "%s : base_name: %s, size: 0x%zx\n", info->name, info->base_name, info->file_size);
#endif

    showSentFileInfo(
        FT_INFO_LABEL_SENDING,
        info->sha256,
        info->file_size,
        info->base_name,
        info->base_name_ln,
        info->name,
        false
    );
    
    
    rtd = (PFT_RECEIVE_THREAD_DATA)malloc(sizeof(FT_RECEIVE_THREAD_DATA));
    if ( rtd == NULL )
    {
        logger.logError(loggerId, GetLastError(), "malloc PFT_RECEIVE_THREAD_DATA failed\n");
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }
    ZeroMemory(rtd, sizeof(FT_RECEIVE_THREAD_DATA));

    // start receiving loop thread with the connected socket
    ft_recv_obj.running = true;
    if ( ft_recv_obj.thread_id == 0 )
    {
        rtd->Sizes = pSizes;
        rtd->type = type;
        rtd->running = &ft_recv_obj.running;
        rtd->ftd = ftd;
        rtd->name = nick;

        ft_recv_obj.thread = CreateThread(
                                NULL,      // default security attributes
                                0,         // use default stack size  
                                recvFTDataThread,    // thread function name
                                rtd,     // argument to thread function 
                                CREATE_SUSPENDED,        // use default creation flags 
                                &ft_recv_obj.thread_id    // returns the thread identifier 
                            );
        if ( ft_recv_obj.thread == NULL )
        {
            // cleaned up later
            //free(rtd);
            //rtd = NULL;

            s = GetLastError();
            logger.logError(loggerId, s, "CreateThread ft receive failed\n");
            goto clean;
        }

        ft_recv_obj.flags |= FT_FLAG_RUNNING;
        ResumeThread(ft_recv_obj.thread);
        CloseHandle(ft_recv_obj.thread);
        ft_recv_obj.thread = NULL;
    }

clean:
    //if ( s != 0 )
    //{
    //    ft_recv_obj.flags = 0;
    //};

    return s;
}

int handleFileDataMessage(
    _In_ PVOID data, 
    _In_ ULONG dataSize,
    _In_ SecPkgContext_StreamSizes* pSizes,
    _Out_ bool* ft_finished
)
{
    int s = 0;

#ifdef DEBUG_PRINT_MESSAGE
    logger.logInfo(loggerId, 0, "MSG_TYPE_FILE_DATA:\n");
#endif
    *ft_finished = false;

    if ( ftd == NULL )
    {
        s = SCHAT_ERROR_OUT_OF_ORDER;
        logger.logError(loggerId, s, "FILE_TRANSFER_DATA not initialized\n");
        return s;
    }

    PSCHAT_FILE_DATA_HEADER blob = (PSCHAT_FILE_DATA_HEADER)data;
    size_t block_size = dataSize - sizeof(SCHAT_BASE_HEADER);

    if ( block_size == 0 )
    {
        s = SCHAT_ERROR_FT_CANCELED;
        logger.logError(loggerId, s, "Data message cancelled\n");
        goto clean;
    }

#ifdef DEBUG_PRINT_HEX_DUMP
    PrintHexDump((ULONG)block_size, blob->data);
#endif

    s = saveFile(ftd, blob->data, block_size);
    showProgress(ftd->written, ftd->size);

clean:
    // error or finished
    if ( s != 0 || ftd->file == NULL )
    {
        const char* label = (s==0)?FT_INFO_LABEL_RECEIVED:FT_INFO_LABEL_CANCELED;
        const char* name = (s==SCHAT_ERROR_FT_CANCELED) ? other_name : nick;
        bool self = (s==SCHAT_ERROR_FT_CANCELED) ? false : true;
        //if ( s == 0 )
        {
            sendReceivedFileInfo(
                s==0,
                ftd->path, 
                label,
                name,
                self,
                rtd->Socket,
                &rtd->Context,
                pSizes,
                rtd->pbIoBuffer,
                rtd->cbIoBuffer
            );
        }
        *ft_finished = (ftd->file == NULL);
    }

    return s;
}

// Disconneting is the only option to tell the sender, that it's canceled.
// In case we don't want to send a received reply after each packet arrived.
// Sender will clean, if error occurs.
// Sending a cancelled msg would be nice, but the normal message socket would have to be used.
// This runs on a different thread and may be in use causing trouble.
// Creating another ft meta communication socket would be an option
int cancelFileReceive()
{
    
    if ( ft_recv_obj.thread != NULL )
    {
        CancelSynchronousIo(
            ft_recv_obj.thread
        );
    }

    if ( !rtd || !ftd )
        return 0;

    //if ( rtd )
    //{
    //    // unblock accept / connect
    //    u_long iMode = 1;
    //    ioctlsocket(ListenSocket, FIONBIO, &iMode);
    //    iMode = 0;
    //    ioctlsocket(ListenSocket, FIONBIO, &iMode);
    //}
    // ???
    // 
    //if ( rtd )
    //{
    //    shutdown(rtd->Socket, SD_BOTH);
    //}

    const char* base_name = NULL;
    size_t base_name_ln = getBaseName(ftd->path, ftd->path_ln, &base_name);
    showSentFileInfo(
        FT_INFO_LABEL_CANCELED,
        NULL,
        ftd->size,
        base_name,
        base_name_ln,
        nick,
        true
    );
    cleanFileReceive(false);

    return 0;
}

int cleanFileReceive(
    bool success
)
{
    mtx.lock();

    // stop receiving loop in thread, if still running
    ft_recv_obj.running = false;

    if ( rtd )
    {
        disconnectFTRecvSocket(
            &rtd->Socket, 
            &rtd->Context, 
            &hServerCreds, 
            rtd->type
        );

        if ( rtd->pbIoBuffer )
            HeapFree(GetProcessHeap(), 0, rtd->pbIoBuffer);

        free(rtd);
        rtd = NULL;
    }

    if ( ftd != NULL )
    {
        if ( ftd->file != NULL )
        {
            fclose(ftd->file);
            if ( !success )
            {
                remove(ftd->path);
            }
        }
        free(ftd);
        ftd = NULL;
    }

    // thread closes after handleMessage finishes and breaks out of receiveSChannelData
    togglePBar(FALSE);
    toggleFileBtn(FILE_TRANSFER_STATUS::STOPPED);
    
    if ( ft_recv_obj.thread != NULL )
        CloseHandle(ft_recv_obj.thread);
    ft_recv_obj.thread = NULL;
    ft_recv_obj.thread_id = 0;
    
    ft_recv_obj.flags = 0;

    mtx.unlock();

    return 0;
}
