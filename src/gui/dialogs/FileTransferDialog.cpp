#include <string>

#include "FileTransferDialog.h"


//Message handler for connection data
INT_PTR CALLBACK FileTransferDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    BaseDlg = hDlg;
    PCHAR BaseName = (PCHAR)lParam;

    switch ( message )
    {
        case WM_INITDIALOG:
            fillInputs(BaseName);
            break;

        case WM_COMMAND:
            return onCommand(hDlg, message, wParam, lParam);
            break;
    }
    return BasicDialog::openCb(hDlg, message, wParam, lParam);
}

INT_PTR FileTransferDialog::onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    return BasicDialog::onCommand(hDlg, message, wParam, lParam);
}

VOID FileTransferDialog::fillInputs(PCHAR BaseName)
{
    SetDlgItemTextA(BaseDlg, IDC_ACCEPT_FILE_IPT, BaseName);
}
