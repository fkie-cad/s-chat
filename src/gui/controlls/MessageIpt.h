#pragma once


#include <shellapi.h>

#include "../keyCodes.h"



LRESULT CALLBACK MesageIptSC(
    HWND Wnd, 
    UINT Msg, 
    WPARAM wParam,
    LPARAM lParam, 
    UINT_PTR IdSubclass, 
    DWORD_PTR RefData
)
{
    LRESULT result = 0;
    (IdSubclass);(RefData);

    switch (Msg)
    {
        case WM_CHAR :
            switch ( wParam ) {
                case VK_RETURN :
                    onSend(Wnd);
                    return 0;
            }

        //case WM_DROPFILES:
        //{
        //    CHAR buffer[MAX_PATH + MSG_CMD_FILE_LN];
        //    StringCchPrintfA(buffer, MSG_CMD_FILE_LN+1, "%s", MSG_CMD_FILE); // +1 for '0' termination
        //    UINT s = DragQueryFileA((HDROP)wParam, 0, &buffer[MSG_CMD_FILE_LN], MAX_PATH-1);
        //    if ( s )
        //    {
        //        buffer[MAX_PATH + MSG_CMD_FILE_LN - 1] = 0;
        //        SetWindowTextA(Wnd, buffer);
        //    }
        //    DragFinish((HDROP)wParam);
        //    break;
        //}

       default:
           result = DefSubclassProc(Wnd, Msg, wParam, lParam);
    } 

    return result;
}

BOOL isEmptyMessage(
    PCHAR Msg, 
    INT MsgCch
)
{
    PCHAR ptr = Msg;
    INT vCount = 0;

    while ( *ptr != 0 )
    {
        if (
            *ptr == '\n' 
            || *ptr == '\r' 
            || *ptr == ' ' 
            || *ptr == '\t' 
            )
            vCount++;

        ++ptr;
    }

    return vCount >= MsgCch;
}
