#ifndef _TOOL_TIP_H
#define _TOOL_TIP_H

#include <windows.h>



class ToolTip
{
    public:
        static
        HWND forChildId(INT ChildId, HWND Parent, const char* Text);

        static
        HWND forChild(HWND Child, HWND Parent, const char* Text);

        static
        void forWindow(HWND Parent, const char* Text);
        
        static
        void forRect(HWND Parent, PRECT Rect, const char* Text);

    private:
};


#endif
