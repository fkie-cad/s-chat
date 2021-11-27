#include <sstream>

#include "ConfirmCloseDialog.h"
#include "../../values.h"


//Message handler for connection data
INT_PTR CALLBACK ConfirmCloseDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
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

INT_PTR ConfirmCloseDialog::onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    return BasicDialog::onCommand(hDlg, message, wParam, lParam);
}

VOID ConfirmCloseDialog::fillInputs(LPARAM lParam)
{
    PCOMFIRM_CLOSE_PARAMS p = (PCOMFIRM_CLOSE_PARAMS)lParam;

    SetDlgItemTextA(BaseDlg, IDC_CCL_ST_IPT, p->Status);
    SetDlgItemTextA(BaseDlg, IDC_CCL_SG_IPT, p->Suggestion);
}
