#include "subEditControl.h"

#include <shobjidl.h>

#include "../keyCodes.h"


LRESULT CALLBACK HexEditControl(
    HWND hWnd, 
    UINT msg, 
    WPARAM wParam,
    LPARAM lParam, 
    UINT_PTR uIdSubclass, 
    DWORD_PTR dwRefData
)
{
    LRESULT result = 0;
    (uIdSubclass);(dwRefData);

    switch (msg)
    {
        case WM_CHAR:
        {
            if ( !( 
                    ( 
                           (wParam >= '0' && wParam <= '9') 
                        || (wParam >= 'A' && wParam <= 'F') 
                        || (wParam >= 'a' && wParam <= 'f') 
                     )
                    || wParam == VK_RETURN
                    || wParam == VK_CONTROL
                    || wParam == VK_DELETE
                    || wParam == VK_BACK
                    || wParam == VK_CTRL_A
                    || wParam == VK_CTRL_C
                    || wParam == VK_CTRL_V
                    || wParam == VK_CTRL_X
                  )
               )
            {
                return 0;
            }
        }

       default:
           result = DefSubclassProc(hWnd, msg, wParam, lParam);
    } 

    return result;
}


LRESULT CALLBACK IpEditControl(
    HWND hWnd, 
    UINT msg, 
    WPARAM wParam,
    LPARAM lParam, 
    UINT_PTR uIdSubclass, 
    DWORD_PTR dwRefData
)
{
    LRESULT result = 0;
    (uIdSubclass);(dwRefData);

    switch (msg)
    {
        case WM_CHAR:
        {
            if ( !( 
                    ( 
                           (wParam >= '0' && wParam <= '9') 
                        || (wParam >= 'A' && wParam <= 'F') 
                        || (wParam >= 'a' && wParam <= 'f') 
                     )
                    || wParam == '.' || wParam == ':'
                    || wParam == VK_RETURN
                    || wParam == VK_CONTROL
                    || wParam == VK_DELETE
                    || wParam == VK_BACK
                    || wParam == VK_CTRL_A
                    || wParam == VK_CTRL_C
                    || wParam == VK_CTRL_V
                    || wParam == VK_CTRL_X
                  )
               )
            {
                return 0;
            }
        }

       default:
           result = DefSubclassProc(hWnd, msg, wParam, lParam);
    } 

    return result;
}
