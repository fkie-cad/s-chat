#include "utils.h"

void AppendWindowTextA(HWND ctrl, PCHAR Text)
{
    // get the current selection
    DWORD StartPos, EndPos;
    SendMessage( ctrl, EM_GETSEL, reinterpret_cast<WPARAM>(&StartPos), reinterpret_cast<WPARAM>(&EndPos) );

    // move the caret to the end of the text
    int outLength = GetWindowTextLength( ctrl );
    SendMessage( ctrl, EM_SETSEL, outLength, outLength );

    // insert the text at the new caret position
    std::string t = std::string(Text)+"\r\n";
    SendMessage( ctrl, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(t.c_str()) );

    // restore the previous selection
    SendMessage( ctrl, EM_SETSEL, StartPos, EndPos );
}
