#include <sstream>

#include "AboutDialog.h"
#include "../../version.h"



INT_PTR CALLBACK AboutDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    BaseDlg = hDlg;
    
    switch ( message )
    {
        case WM_INITDIALOG:
            fillInputs(lParam);
            break;
            
    }
    return BasicDialog::openCb(hDlg, message, wParam, lParam);
}

INT_PTR AboutDialog::onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    return BasicDialog::onCommand(hDlg, message, wParam, lParam);
}

VOID AboutDialog::fillInputs(LPARAM lParam)
{
    char msg[0x100];
    PABOUT_DIALOG_PARAMS params = (PABOUT_DIALOG_PARAMS) lParam;

    sprintf_s(msg, 0x100, "%s, Version: %s", params->BinaryName, params->ActVersion);
    SetDlgItemTextA(BaseDlg, IDC_ABT_VS_IPT, msg);

    sprintf_s(msg, 0x100, "Last changed: %s", params->LastChanged);
    SetDlgItemTextA(BaseDlg, IDC_ABT_LC_IPT, msg);

    sprintf_s(msg, 0x100, "Compiled: %s -- %s", params->CompileDate, params->CompileTime);
    SetDlgItemTextA(BaseDlg, IDC_ABT_CP_IPT, msg);
}
