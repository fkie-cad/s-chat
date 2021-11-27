 #include "guiBridge.h"

#include <string.h>
#include <stdint.h>
#include <Mmsystem.h>
#include <Commctrl.h>

#include <mutex>

#include "dbg.h"

PARAFORMAT InfoFmt;
PARAFORMAT LocalFmt;
PARAFORMAT RemoteFmt;
bool InfoFmtInitialized = false;
bool LocalFmtInitialized = false;
bool RemoteFmtInitialized = false;


extern int last_type;

static HWND InfoStatusOpt = NULL;
static HWND ConnStatusOpt = NULL;
static HWND MessageOutput = NULL;
//static HWND ThumbPrintOutput = NULL;
static HWND FilePBar = NULL;
static std::mutex msg_mtx;
static std::mutex status_mtx;
static std::mutex pg_mtx;

extern HWND MainWindow;
extern HGLOBAL notify_snd;

static ULONG InfoStatusThreadId = 0;
static HANDLE InfoStatusThread = NULL;


void initFormats()
{
    if ( !InfoFmtInitialized )
    {
        ZeroMemory(&InfoFmt, sizeof(InfoFmt));
        InfoFmt.cbSize = sizeof(InfoFmt);
        InfoFmt.dwMask = PFM_ALIGNMENT;
        InfoFmt.wAlignment = PFA_CENTER;

        InfoFmtInitialized = true;
    }
    if ( !LocalFmtInitialized )
    {
        ZeroMemory(&LocalFmt, sizeof(LocalFmt));
        LocalFmt.cbSize = sizeof(LocalFmt);
        LocalFmt.dwMask = PFM_ALIGNMENT;
        LocalFmt.wAlignment = PFA_RIGHT;

        LocalFmtInitialized = true;
    }
    if ( !RemoteFmtInitialized )
    {
        ZeroMemory(&RemoteFmt, sizeof(RemoteFmt));
        RemoteFmt.cbSize = sizeof(RemoteFmt);
        RemoteFmt.dwMask = PFM_ALIGNMENT;
        RemoteFmt.wAlignment = PFA_LEFT;

        RemoteFmtInitialized = true;
    }
}

void setConnStatusOutput(
    _In_ HWND Output_
)
{
    ConnStatusOpt = Output_;
}

void setInfoStatusOutput(
    _In_ HWND Output_
)
{
    InfoStatusOpt = Output_;
}

void setMessageOutput(
    _In_ HWND MessageOutput_
)
{
    MessageOutput = MessageOutput_;
}

void setFilePBar(
    _In_ HWND hwdn
)
{
    FilePBar = hwdn;
}

//void setThumbPrintOutput(
//    _In_ HWND ThumbPrintOutput_
//)
//{
//    ThumbPrintOutput = ThumbPrintOutput_;
//}

void showConnStatus(
    _In_ const char* msg
)
{
    if ( ConnStatusOpt == NULL )
        return;
    //if ( status_mtx.try_lock() )
    {
        status_mtx.lock();
        SetWindowTextA(ConnStatusOpt, msg);
        status_mtx.unlock();
    }
}


#define SHOW_STATUS_DURATION (2000)
DWORD WINAPI InfoStatusFade(LPVOID lpParam)
{
    (lpParam);
    Sleep(SHOW_STATUS_DURATION);
    SetWindowTextA(InfoStatusOpt, "");
    return 0;
}

void showInfoStatus(
    _In_ const char* msg
)
{
    if ( InfoStatusOpt == NULL )
        return;

    //status_mtx.lock();
    SetWindowTextA(InfoStatusOpt, msg);

    if ( InfoStatusThread != NULL )
    {
        TerminateThread(InfoStatusThread, 0);
        CloseHandle(InfoStatusThread);
        InfoStatusThread = NULL;
        InfoStatusThreadId = 0;
    }

    InfoStatusThread = CreateThread(
            NULL,                   // default security attributes
            0,                      // use default stack size  
            InfoStatusFade,       // thread function name
            NULL,          // argument to thread function 
            0,                      // use default creation flags 
            &InfoStatusThreadId    // returns the thread identifier 
        );
    //T = NULL;
    //status_mtx.unlock();
}

//#include <richedit.h>
void AppendWindowTextA(
    _In_ HWND ctrl, 
    _In_ PCHAR Text, 
    _In_ PARAFORMAT* fmt
)
{
    // get the current selection
    DWORD StartPos, EndPos;
    SendMessage(ctrl, EM_GETSEL, (WPARAM)(&StartPos), (WPARAM)(&EndPos));

    // move the caret to the end of the text
    int outLength = GetWindowTextLength(ctrl);
    SendMessage(ctrl, EM_SETSEL, outLength, outLength);
    
    // insert the text at the new caret position
    SendMessage(ctrl, EM_REPLACESEL, TRUE, (LPARAM)(Text));
    
    outLength = GetWindowTextLength(ctrl);
    SendMessage(ctrl, EM_SETSEL, outLength, outLength);
    SendMessage(ctrl, EM_REPLACESEL, TRUE, (LPARAM)("\r\n"));
    
    if ( fmt != NULL )
    {
        //SendMessage(ctrl, EM_SETSEL, outLength, outLength+t.size());
        //SendMessage(ctrl, EM_SETPARAFORMAT, 0, (LPARAM)fmt);

        //CHARFORMATA cfmt;
        //ZeroMemory(&cfmt, sizeof(cfmt));
        //cfmt.cbSize = sizeof(cfmt);
        //cfmt.dwMask = CFM_COLOR;
        //if ( fmt->wAlignment == PFA_LEFT )
        //    cfmt.crTextColor = RGB(0,100,100);
        //else if ( fmt->wAlignment == PFA_RIGHT )
        //    cfmt.crTextColor = RGB(100,100,0);
        //else
        //    cfmt.crTextColor = RGB(0,0,0);
        //SendMessage(ctrl, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cfmt);
    }

    // restore the previous selection
    SendMessage(ctrl, EM_SETSEL, StartPos, EndPos);

    // scroll to end
    //SendMessage(ctrl, EM_SCROLL, SB_PAGEDOWN, 0);
    SendMessage(ctrl, EM_SCROLL, SB_BOTTOM, 0L);
}

BOOL playSound(
    _In_ HGLOBAL hRes
)
{ 
    BOOL s = 0; 
    LPCSTR res; 

    res = (LPCSTR)LockResource(hRes);
    if ( res != NULL )
    { 
        s = sndPlaySound(res, SND_MEMORY | SND_SYNC | SND_NODEFAULT); 
        UnlockResource(hRes); 
    } 
 
    return s; 
} 

ULONG sound_thread_id;
HANDLE sound_thread;

ULONG notify(
    _In_ LPVOID lpParam
)
{
    UNREFERENCED_PARAMETER(lpParam);
    if ( notify_snd == NULL )
        return (ULONG)-1;
    playSound(notify_snd);
    sound_thread_id = 0;
    return 0;
}

#define UINT8_TO_CHAR2(_i_, _s_) { \
    if ( _i_ < 10 ) { _s_[0] = '0'; _itoa_s(_i_, &_s_[1], 2, 10); }\
    else { _itoa_s(_i_, &_s_[0], 3, 10); } \
    _s_[2] = 0; \
}

void showMessages(
    _In_ PSCHAT_MESSAGE_HEADER message, 
    _In_ BOOL self
)
{
    //showStatus("showMessages");
    if ( MessageOutput == NULL )
        return;

    int type = (self) ? 1 : 2;

    initFormats();
    PARAFORMAT* fmt = NULL;
    std::string msg;
    if ( self )
    {
        fmt = &LocalFmt;
    }
    else 
    {
        fmt = &RemoteFmt;
    }

    if ( last_type != type )
    {
        SYSTEMTIME sts;
        GetLocalTime(&sts);

        char hours[3];
        char minutes[3];
        UINT8_TO_CHAR2(sts.wHour, hours);
        UINT8_TO_CHAR2(sts.wMinute, minutes);

        msg = "\r\n== "+std::string(message->name) + " (" + std::string(hours) + ":" + std::string(minutes) + ") ==\r\n";
    }
    msg += std::string((char*)message->data);

    msg_mtx.lock();
    last_type = type;
    AppendWindowTextA(MessageOutput, &msg[0], fmt);
    msg_mtx.unlock();

    if ( !self )
    {
        HWND fgwnd = GetForegroundWindow();
        if ( fgwnd != MainWindow && sound_thread_id == 0 )
        {
            sound_thread = CreateThread(
                    NULL,      // default security attributes
                    0,         // use default stack size  
                    notify,    // thread function name
                    NULL,     // argument to thread function 
                    0,        // use default creation flags 
                    &sound_thread_id    // returns the thread identifier 
                );
            CloseHandle(sound_thread);
            sound_thread = NULL;
        }
    }
}

void showMessages(
    _In_ char* message, 
    _In_ UINT type
)
{
    //showStatus("showMessages");
    if ( MessageOutput == NULL )
        return;

    initFormats();
    PARAFORMAT* fmt = NULL;
    if ( type == MSG_TYPE_INFO   )
        fmt = &InfoFmt;
    else if ( type == MSG_TYPE_LOCAL   )
        fmt = &LocalFmt;
    else if ( type == MSG_TYPE_LOCAL   )
        fmt = &RemoteFmt;

    msg_mtx.lock();
    AppendWindowTextA(MessageOutput, message, fmt);
    msg_mtx.unlock();
}

void showCertSha(
    _In_ const char* hash
)
{
    char msg[SHA1_STRING_BUFFER_LN + 7];
    sprintf_s(msg, (SHA1_STRING_BUFFER_LN + 6), "cert: %s", hash);
    showMessages(msg, MSG_TYPE_INFO);
}

#define PG_STRING_SIZE (0x1f)
void showProgress(
    _In_ size_t v, 
    _In_ size_t s
)
{
    uint8_t percent = (uint8_t) ( (float)v / s*100 );
    char pc[PG_STRING_SIZE];
    sprintf_s(pc, PG_STRING_SIZE, "0x%zx / 0x%zx (%u%%)", v, s, percent);
    pc[PG_STRING_SIZE-1] = 0;
    showInfoStatus(pc);
    
    if ( FilePBar == NULL )
        return;

    //pg_mtx.lock();
    SendMessage(FilePBar, PBM_SETPOS, percent, 0);
    //pg_mtx.unlock();
}

void togglePBar(
    _In_ BOOL state
)
{
    if ( state )
        ShowWindow(FilePBar, SW_SHOW);
    else
        ShowWindow(FilePBar, SW_HIDE);
}
