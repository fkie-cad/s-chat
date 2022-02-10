#ifndef GUI_BRIDGE_H
#define GUI_BRIDGE_H

#include <windows.h>
#include <richedit.h>

#include "values.h"
#include "schannel/connection.h"
#include "gui/gui.h"

#define MSG_TYPE_INFO (0x1)
#define MSG_TYPE_LOCAL (0x2)
#define MSG_TYPE_REMOTE (0x3)


void setConnStatusOutput(
    _In_ HWND Output_
);

void setInfoStatusOutput(
    _In_ HWND Output_
);

void setMessageOutput(
    _In_ HWND MessageOutput_
);

void setFilePBar(
    _In_ HWND hwdn
);

//void setThumbPrintOutput(
//    _In_ HWND ThumbPrintOutput_
//);

void showConnStatus(
    _In_ const char* msg
);

void showInfoStatus(
    _In_ const char* msg,
    _In_ bool fade=true
);

void checkFillingState(
    _In_ HWND ctrl, 
    _In_ SIZE_T NextLength, 
    _In_ INT Type
);

void AppendWindowTextA(
    _In_ HWND ctrl, 
    _In_ PCHAR Text, 
    _In_opt_ PARAFORMAT* fmt
);

void showMessages(
    _In_ PSCHAT_MESSAGE_HEADER message, 
    _In_ BOOL self
);

void showMessages(
    _In_ char* message, 
    _In_ UINT type
);

void showCertSha(
    _In_ const char* hash
);

void showProgress(
    _In_ size_t v, 
    _In_ size_t s
);

void togglePBar(
    _In_ BOOL state
);

#endif
