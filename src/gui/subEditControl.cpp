#include "subEditControl.h"

#include <shobjidl.h>


LRESULT CALLBACK HexEditControl(HWND hWnd, UINT msg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
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
                    || wParam == 0x01 // CTRL-A
                    || wParam == 0x03 // CTRL-C
                    || wParam == 0x16 // CTRL-V
                    || wParam == 0x18 // CTRL-X
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

LRESULT CALLBACK IpEditControl(HWND hWnd, UINT msg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
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
                    || wParam == 0x01 // CTRL-A
                    || wParam == 0x03 // CTRL-C
                    || wParam == 0x16 // CTRL-V
                    || wParam == 0x18 // CTRL-X
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
