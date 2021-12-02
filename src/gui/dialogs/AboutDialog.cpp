#include <sstream>

#include "AboutDialog.h"
#include "../../version.h"



INT_PTR CALLBACK AboutDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    BaseDlg = hDlg;
    
    switch ( message )
    {
        case WM_INITDIALOG:
            fillInputs();
            break;
            
    }
    return BasicDialog::openCb(hDlg, message, wParam, lParam);
}

INT_PTR AboutDialog::onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    return BasicDialog::onCommand(hDlg, message, wParam, lParam);
}

VOID AboutDialog::fillInputs()
{
    char msg[0x100];

    sprintf_s(msg, 0x100, "%s, Version: %s", REL_NAME, REL_VS);
    SetDlgItemTextA(BaseDlg, IDC_ABT_VS_IPT, msg);

    sprintf_s(msg, 0x100, "Last changed: %s", REL_DATE);
    SetDlgItemTextA(BaseDlg, IDC_ABT_LC_IPT, msg);

    sprintf_s(msg, 0x100, "Compiled: %s -- %s", COMPILE_DATE, COMPILE_TIME);
    SetDlgItemTextA(BaseDlg, IDC_ABT_CP_IPT, msg);
}
