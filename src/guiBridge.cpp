 #include "guiBridge.h"

#include <string.h>
#include <stdint.h>
#include <Mmsystem.h>
#include <Commctrl.h>

#include <mutex>

#include "dbg.h"

//PARAFORMAT InfoFmt;
//PARAFORMAT LocalFmt;
//PARAFORMAT RemoteFmt;
//bool InfoFmtInitialized = false;
//bool LocalFmtInitialized = false;
//bool RemoteFmtInitialized = false;

#define MSG_TYPE_NONE (0)
#define MSG_TYPE_SELF (1)
#define MSG_TYPE_OTHER (2)

extern int last_type;

static HWND InfoStatusOpt = NULL;
static HWND ConnStatusOpt = NULL;
static HWND MessageOutput = NULL;
static HWND FilePBar = NULL;
static std::mutex msg_mtx;
static std::mutex conn_status_mtx;
static std::mutex info_status_mtx;
static std::mutex pg_mtx;

extern HWND MainWindow;
extern HGLOBAL notify_snd;

extern SIZE_T MessageOptMaxText;
extern SIZE_T MessageOptFillThreash;
extern SIZE_T MessageOptDeleteSize;

static ULONG InfoStatusThreadId = 0;
static HANDLE InfoStatusThread = NULL;


//void initFormats()
//{
//    if ( !InfoFmtInitialized )
//    {
//        ZeroMemory(&InfoFmt, sizeof(InfoFmt));
//        InfoFmt.cbSize = sizeof(InfoFmt);
//        InfoFmt.dwMask = PFM_ALIGNMENT;
//        InfoFmt.wAlignment = PFA_CENTER;
//
//        InfoFmtInitialized = true;
//    }
//    if ( !LocalFmtInitialized )
//    {
//        ZeroMemory(&LocalFmt, sizeof(LocalFmt));
//        LocalFmt.cbSize = sizeof(LocalFmt);
//        LocalFmt.dwMask = PFM_ALIGNMENT;
//        LocalFmt.wAlignment = PFA_RIGHT;
//
//        LocalFmtInitialized = true;
//    }
//    if ( !RemoteFmtInitialized )
//    {
//        ZeroMemory(&RemoteFmt, sizeof(RemoteFmt));
//        RemoteFmt.cbSize = sizeof(RemoteFmt);
//        RemoteFmt.dwMask = PFM_ALIGNMENT;
//        RemoteFmt.wAlignment = PFA_LEFT;
//
//        RemoteFmtInitialized = true;
//    }
//}

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

void showConnStatus(
    _In_ const char* msg
)
{
    if ( ConnStatusOpt == NULL )
        return;

    conn_status_mtx.lock();
    SetWindowTextA(ConnStatusOpt, msg);
    conn_status_mtx.unlock();
}

#define SHOW_STATUS_DURATION (5000)

VOID CALLBACK InfoStatusTimerProc(HWND hwnd, UINT message, UINT idTimer, DWORD dwTime)
{ 
    (hwnd);(message);(idTimer);(dwTime);
    info_status_mtx.lock();
    SetWindowTextA(InfoStatusOpt, "");
    info_status_mtx.unlock();
} 

void showInfoStatus(
    _In_ const char* msg,
    _In_ bool fade
)
{
    if ( InfoStatusOpt == NULL )
        return;

    KillTimer(MainWindow, IDT_INFO_TIMER); 
    if ( fade )
        SetTimer(MainWindow, IDT_INFO_TIMER, SHOW_STATUS_DURATION, (TIMERPROC) InfoStatusTimerProc);

    info_status_mtx.lock();
    SetWindowTextA(InfoStatusOpt, msg);
    info_status_mtx.unlock();
}

#undef SHOW_STATUS_DURATION


/**
 * Check text box filling
 * 
 * Type 1:
 * If filling exceeds threshold, delete some chars.
 * TODO: opt in for autosaving these chars
 */
void checkFillingState(
    _In_ HWND ctrl, 
    _In_ SIZE_T NextLength, 
    _In_ INT Type
)
{
    (Type);
    SIZE_T TextSize = GetWindowTextLengthA(ctrl) + NextLength;

    //std::string ms = "message size: "+std::to_string(TextSize)+" / "+std::to_string(MessageOptFillThreash);
    //showInfoStatus(ms.c_str());

    if ( GetWindowTextLengthA(ctrl) < MessageOptDeleteSize )
        return;

    if ( TextSize > MessageOptFillThreash )
    {
        // get the current selection
        //DWORD StartPos, EndPos;
        //SendMessageA(ctrl, EM_GETSEL, (WPARAM)(&StartPos), (WPARAM)(&EndPos));

        // select some text at the beginning
        SendMessageA(ctrl, EM_SETSEL, 0, (WPARAM)MessageOptDeleteSize);
    
        // insert clear the selection
        SendMessageA(ctrl, EM_REPLACESEL, FALSE, NULL);
    
        // restore the previous selection
        //SendMessageA(ctrl, EM_SETSEL, StartPos, EndPos);

        // scroll to end
        SendMessageA(ctrl, EM_SCROLL, SB_BOTTOM, 0L);
    }
}

//#include <richedit.h>
void AppendWindowTextA(
    _In_ HWND ctrl, 
    _In_ PCHAR Text, 
    _In_opt_ PARAFORMAT* fmt
)
{
    int outLength;

    checkFillingState(ctrl, strlen(Text)+3, 1);

    // get the current selection
    DWORD StartPos, EndPos;
    SendMessageA(ctrl, EM_GETSEL, (WPARAM)(&StartPos), (WPARAM)(&EndPos));

    // move the caret to the end of the text, replace text
    outLength = GetWindowTextLengthA(ctrl);
    SendMessageA(ctrl, EM_SETSEL, outLength, outLength);
    SendMessageA(ctrl, EM_REPLACESEL, TRUE, (LPARAM)(Text));
    
    outLength = GetWindowTextLengthA(ctrl);
    SendMessageA(ctrl, EM_SETSEL, outLength, outLength);
    SendMessageA(ctrl, EM_REPLACESEL, TRUE, (LPARAM)("\r\n"));
    
    (fmt);
    //if ( fmt != NULL )
    //{
    //    SendMessage(ctrl, EM_SETSEL, outLength, outLength+oldLength);
    //    SendMessage(ctrl, EM_SETPARAFORMAT, 0, (LPARAM)fmt);

    //    CHARFORMATA cfmt;
    //    ZeroMemory(&cfmt, sizeof(cfmt));
    //    cfmt.cbSize = sizeof(cfmt);
    //    cfmt.dwMask = CFM_COLOR;
    //    if ( fmt->wAlignment == PFA_LEFT )
    //        cfmt.crTextColor = RGB(0,100,100);
    //    else if ( fmt->wAlignment == PFA_RIGHT )
    //        cfmt.crTextColor = RGB(100,100,0);
    //    else
    //        cfmt.crTextColor = RGB(0,0,0);
    //    SendMessage(ctrl, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cfmt);
    //}

    // restore the previous selection
    SendMessageA(ctrl, EM_SETSEL, StartPos, EndPos);

    // scroll to end
    SendMessageA(ctrl, EM_SCROLL, SB_BOTTOM, 0L);
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
        s = sndPlaySoundA(res, SND_MEMORY | SND_SYNC | SND_NODEFAULT); 
        UnlockResource(hRes); 
    } 
 
    return s; 
} 

ULONG sound_thread_id;
HANDLE sound_thread;

ULONG WINAPI notify(
    _In_ LPVOID lpParam
)
{
    (lpParam);

    if ( notify_snd == NULL )
        return (ULONG)-1;
    playSound(notify_snd);
    sound_thread_id = 0;
    return 0;
}

#define TIMEUINT_TO_CHAR2(_i_, _s_) { \
    if ( _i_ < 0 || _i_ > 60 ) { _s_[0] = 0; _s_[1] = 0; }\
    else if ( _i_ < 10 ) { _s_[0] = '0'; _s_[1] = (char)(_i_+0x30); }\
    else { _s_[0] = (char)((_i_/10)+0x30); _s_[1] = (char)((_i_%10)+0x30); } \
    _s_[2] = 0; \
} 

void showMessages(
    _In_ PSCHAT_MESSAGE_HEADER message, 
    _In_ BOOL self
)
{
    if ( MessageOutput == NULL )
        return;

    int type = (self) ? MSG_TYPE_SELF : MSG_TYPE_OTHER;

    //initFormats();
    PARAFORMAT* fmt = NULL;
    //std::string msg;
    PCHAR msg = NULL;
    SIZE_T msgSize = 0;
    //if ( self )
    //{
    //    fmt = &LocalFmt;
    //}
    //else 
    //{
    //    fmt = &RemoteFmt;
    //}

    msgSize = strlen(message->name) + message->data_ln + 0x20;
    msg = new CHAR[msgSize];
    int w = 0;
    if ( !msg )
        return;
    
    msg_mtx.lock();

    if ( last_type != type )
    {
        SYSTEMTIME sts;
        GetLocalTime(&sts);

        char hours[3];
        char minutes[3];
        TIMEUINT_TO_CHAR2(sts.wHour, hours);
        TIMEUINT_TO_CHAR2(sts.wMinute, minutes);

        w = sprintf_s(
            msg, msgSize, 
            "\r\n== %s (%s:%s) ==\r\n", 
            message->name, hours, minutes);
    }
    w = sprintf_s(&msg[w], msgSize-w, "%s", (char*)message->data);

    last_type = type;
    AppendWindowTextA(MessageOutput, msg, fmt);

    msg_mtx.unlock();

    delete[] msg;

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
            if ( sound_thread )
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

    (type);
    //initFormats();
    PARAFORMAT* fmt = NULL;
    //if ( type == MSG_TYPE_INFO   )
    //    fmt = &InfoFmt;
    //else if ( type == MSG_TYPE_LOCAL   )
    //    fmt = &LocalFmt;
    //else if ( type == MSG_TYPE_LOCAL   )
    //    fmt = &RemoteFmt;

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
    
    showInfoStatus(pc, false);
    
    if ( FilePBar == NULL )
        return;

    //pg_mtx.lock();
    SendMessage(FilePBar, PBM_SETPOS, percent, 0);
    //pg_mtx.unlock();
}
#undef PG_STRING_SIZE

void togglePBar(
    _In_ BOOL state
)
{
    if ( state )
        ShowWindow(FilePBar, SW_SHOW);
    else
        ShowWindow(FilePBar, SW_HIDE);
}
