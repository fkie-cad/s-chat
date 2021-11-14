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
    PSCHAT_BASE_HEADER base = (PSCHAT_BASE_HEADER)data;
    bool ft_finished = false;

#ifdef DEBUG_PRINT_MESSAGE
    fprintf(out, "handleMessage %.*s:\n", 8, (CHAR*)&base->type);
#endif

    if ( dataSize < sizeof(SCHAT_BASE_HEADER) || dataSize < base->size )
    {
        fprintf(out, "received corrupted message:\n");
        PrintHexDump(dataSize, data, out);
#ifdef GUI
        showStatus("corrupted data");
#endif
        *running = FALSE;
        s = SCHAT_ERROR_CORRUPTED_DATA;
        goto clean;
    }

    // stop the receiving loop
    if ( base->flags & MSG_FLAG_STOP )
    {
        *running = FALSE;
    }
    
    if ( base->type == MSG_TYPE_TEXT )
    {
        s = handleTextMessage(
                data, 
                dataSize
            );
    }
    else if ( base->type == MSG_TYPE_FT_STATUS )
    {
        s = handleFTStatusMessage(
                data, 
                dataSize
            );
    }
    else if ( base->type == MSG_TYPE_FILE_INFO )
    {
        s = handleFileInfoMessage(
                data, 
                dataSize,
                pSizes,
                type
            );
    }
    else if ( base->type == MSG_TYPE_FILE_DATA )
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
        fprintf(out, "received unknown msg type:\n");
        PrintHexDump(dataSize, data, out);
#ifdef GUI
        showStatus("unknown data");
#endif
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
    fprintf(out, "MSG_TYPE_TEXT:\n");
#endif
    PSCHAT_MESSAGE_HEADER message = (PSCHAT_MESSAGE_HEADER)data;
    message->name[MAX_NAME_LN-1] = 0;
    ((CHAR*)data)[dataSize-1] = 0;
#ifdef DEBUG_PRINT_MESSAGE
    fprintf(out, "%s : %s\n", message->name, message->data);
#endif
#ifdef GUI
    showMessages(message, FALSE);
#endif

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
    fprintf(out, "MSG_TYPE_FT_STATUS:\n");
#endif
    PSCHAT_FILE_STATUS_HEADER message = (PSCHAT_FILE_STATUS_HEADER)data;
    
    // fills other name for sender side
    strcpy_s(other_name, MAX_NAME_LN, message->name);
    other_name[MAX_NAME_LN-1] = 0;

    if ( message->bh.flags & MSG_FLAG_CANCEL )
    {
#ifdef GUI
        showSentFileInfo(
            FT_INFO_LABEL_CANCELED,
            NULL,
            0,
            message->base_name,
            message->base_name_ln,
            message->name,
            false
        );
#endif
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
    if ( ft_recv_obj.thread_id != 0 )
    {
        return SCHAT_ERROR_MAX_FT;
    }
    initFTObject(&ft_recv_obj);

    int s = 0;
#ifdef DEBUG_PRINT_MESSAGE
    fprintf(out, "MSG_TYPE_FILE_INFO:\n");
#endif
    PSCHAT_FILE_INFO_HEADER info = (PSCHAT_FILE_INFO_HEADER)data;
    info->name[MAX_NAME_LN-1] = 0;
    info->base_name[info->base_name_ln] = 0;
    ((CHAR*)data)[dataSize-1] = 0;
       
#ifdef DEBUG_PRINT_MESSAGE
    fprintf(out, "file_size: 0x%zx\nbase_name: %s (0x%x)\n", info->file_size, info->base_name, info->base_name_ln);
    fprintf(out, "hash: ");
    printBytes(info->sha256, SHA256_BYTES_LN, 0, "", out);
#endif

    if ( info->file_size == 0 )
    {
        fprintf(out, "ERROR (0x%x): File size is 0.\n", SCHAT_ERROR_FILE_SIZE);
        return SCHAT_ERROR_FILE_SIZE;
    }

    size_t path_ln = strlen(file_dir) + info->base_name_ln + 2; // separator and terminating 0
    
    mtx.lock();
    ftd = (PFILE_TRANSFER_DATA)malloc(sizeof(FILE_TRANSFER_DATA) + path_ln);
    mtx.unlock();
    if ( ftd == NULL )
    {
        fprintf(out, "ERROR (0x%x): malloc FILE_TRANSFER_DATA failed\n", GetLastError());
        return SCHAT_ERROR_NO_MEMORY;
    }

    // construct path
    char* path = ftd->path;
    if ( path == NULL )
    {
        fprintf(out, "ERROR (0x%x): malloc path failed\n", GetLastError());
        return SCHAT_ERROR_NO_MEMORY;
    }
    sprintf_s(path, path_ln, "%s\\%s", ((file_dir==NULL)?".":file_dir), info->base_name);
    path[path_ln-1] = 0;
    ftd->path_ln = path_ln;
    strcpy_s(ftd->name, MAX_NAME_LN, info->name);
    ftd->name[MAX_NAME_LN-1] = 0;

#ifdef DEBUG_PRINT_MESSAGE
    fprintf(out, "file path: %s\n", path);
#endif

    // open FILE*
    FILE* file = NULL;
    s = fopen_s(&file, path, "wb");
    if ( s != 0 )
    {
        fprintf(out, "ERROR (0x%x): open transfer file failed\n", GetLastError());
        return SCHAT_ERROR_OPEN_FILE;
    }

    // fill transfer struct
    ftd->file = file;
    ftd->size = info->file_size;
    ftd->written = 0;
    
    // fills other name for receiver side
    strcpy_s(other_name, MAX_NAME_LN, info->name);
    other_name[MAX_NAME_LN-1] = 0;

#ifdef DEBUG_PRINT_MESSAGE
    fprintf(out, "%s : base_name: %s, size: 0x%zx\n", info->name, info->base_name, info->file_size);
#endif
#ifdef GUI

    showSentFileInfo(
        FT_INFO_LABEL_SENDING,
        info->sha256,
        info->file_size,
        info->base_name,
        info->base_name_ln,
        info->name,
        false
    );
#endif
    
    
    mtx.lock();
    rtd = (PFT_RECEIVE_THREAD_DATA)malloc(sizeof(FT_RECEIVE_THREAD_DATA));
    mtx.unlock();
    if ( rtd == NULL )
    {
        fprintf(out, "ERROR (0x%x): malloc PFT_RECEIVE_THREAD_DATA failed\n", GetLastError());
        s = SCHAT_ERROR_NO_MEMORY;
        goto clean;
    }
    ZeroMemory(rtd, sizeof(FT_RECEIVE_THREAD_DATA));

    // start receiving loop thread with the connected socket
    if ( ft_recv_obj.thread_id == 0 )
    {
        rtd->Sizes = pSizes;
        rtd->type = type;
        rtd->running = &ft_recv_obj.running;
        rtd->ftd = ftd;
        rtd->name = nick;

        mtx.lock();
        ft_recv_obj.thread = CreateThread(
                                NULL,      // default security attributes
                                0,         // use default stack size  
                                recvFTDataThread,    // thread function name
                                rtd,     // argument to thread function 
                                0,        // use default creation flags 
                                &ft_recv_obj.thread_id    // returns the thread identifier 
                            );
        if ( ft_recv_obj.thread == NULL )
        {
            s = GetLastError();
            fprintf(out, "ERROR (0x%x): CreateThread ft receive failed\n", s);
            mtx.unlock();
            goto clean;
        }
        mtx.unlock();
    }

clean:
    ;

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
    fprintf(out, "MSG_TYPE_FILE_DATA:\n");
#endif
    
    if ( ftd == NULL )
    {
        fprintf(out, "ERROR (0x%x): FILE_TRANSFER_DATA not initialized\n", SCHAT_ERROR_OUT_OF_ORDER);
        return SCHAT_ERROR_OUT_OF_ORDER;
    }

    PSCHAT_FILE_DATA_HEADER blob = (PSCHAT_FILE_DATA_HEADER)data;
    size_t block_size = dataSize - sizeof(SCHAT_BASE_HEADER);

    if ( block_size == 0 )
    {
        s = SCHAT_ERROR_FT_CANCELED;
        fprintf(out, "ERROR (0x%x): Data message canceled\n", s);
#ifdef GUI
    //const char* base_name = NULL;
    //size_t base_name_ln = getBaseName(ftd->path, ftd->path_ln, &base_name);
    //showSentFileInfo(
    //    FT_INFO_LABEL_CANCELED,
    //    NULL,
    //    ftd->size,
    //    base_name,
    //    base_name_ln,
    //    ftd->name,
    //    true
    //);
#endif
        goto clean;
    }

#ifdef DEBUG_PRINT_HEX_DUMP
    PrintHexDump((ULONG)block_size, blob->data, out);
#endif

    s = saveFile(ftd, blob->data, block_size, out);
#ifdef GUI
    showProgress(ftd->written, ftd->size);
#endif

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
                rtd->cbIoBuffer,
                out
            );
        }
        *ft_finished = (ftd->file == NULL);
    }

    return s;
}

// Disconneting is the only option to tell the sender, that it's canceled.
// In case we don't want to send a received reply after each packet arrived.
// Sender will clean, if error occurs.
// Sending a canceled msg would be nice, but the normal message socket would have to be used.
// This runs on a different thread and may be in use causing trouble.
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

#ifdef GUI
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
#endif
    cleanFileReceive(false);

    return 0;
}

int cleanFileReceive(
    bool success
)
{
    mtx.lock();

    // stop receiving loop in thread, if still running
    ft_recv_obj.running = FALSE;

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
    }
    rtd = NULL;

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
#ifdef GUI
    togglePBar(FALSE);
    toggleFileBtn(FILE_TRANSFER_STATUS::STOPPED);
#endif
    
    if ( ft_recv_obj.thread != NULL )
        CloseHandle(ft_recv_obj.thread);
    ft_recv_obj.thread = NULL;
    ft_recv_obj.thread_id = 0;
    
    mtx.unlock();

    return 0;
}
