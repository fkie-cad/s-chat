#ifndef __SUB_EDIT_CONTROL_H
#define __SUB_EDIT_CONTROL_H

#include <windows.h>
#include <shobjidl.h>


LRESULT CALLBACK HexEditControl(
    HWND hWnd, 
    UINT msg, 
    WPARAM wParam,
    LPARAM lParam, 
    UINT_PTR uIdSubclass, 
    DWORD_PTR dwRefData
);

LRESULT CALLBACK IpEditControl(
    HWND hWnd, 
    UINT msg, 
    WPARAM wParam,
    LPARAM lParam, 
    UINT_PTR uIdSubclass, 
    DWORD_PTR dwRefData
);

#endif
