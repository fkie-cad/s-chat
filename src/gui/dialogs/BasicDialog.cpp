#include "BasicDialog.h"
#include <commctrl.h>

INT_PTR CALLBACK BasicDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    (lParam);
    INT_PTR result = (INT_PTR)FALSE;

    switch ( message )
    {
        case WM_INITDIALOG:
            centerDialog(hDlg);

            result = TRUE;
            break;

        case WM_COMMAND:
            result = onCommand(hDlg, message, wParam, lParam);
            break;
    }
    return result;
}

INT_PTR BasicDialog::onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    INT_PTR result = 0;

    int wmId = LOWORD(wParam);

    switch ( wmId )
    {
        case IDCANCEL:
        case IDNO:
        case IDOK:
        case IDYES:
            EndDialog(hDlg, LOWORD(wParam));
            break;

        default:
            result = (INT_PTR)DefWindowProcA(hDlg, message, wParam, lParam);
            break;
    }

    return result;
}

VOID BasicDialog::centerDialog(HWND hDlg)
{
    int DlgW, DlgH, MainW, MainH;

    if ( MainWindow == nullptr || hDlg == nullptr )
        return;
            
    GetWindowRect(MainWindow, &MainWindowRect);
    GetWindowRect(hDlg, &DlgRect);
    DlgW = DlgRect.right - DlgRect.left;
    DlgH = DlgRect.bottom - DlgRect.top;
    MainW = MainWindowRect.right - MainWindowRect.left;
    MainH = MainWindowRect.bottom - MainWindowRect.top;

    DlgRect.left = MainWindowRect.left + ((MainW - DlgW) / 2);
    DlgRect.top = MainWindowRect.top + ((MainH - DlgH) / 2);

    MoveWindow(hDlg, DlgRect.left, DlgRect.top, DlgW, DlgH, TRUE);
}

VOID BasicDialog::disableInputs(HWND hDlg, ULONG* iptIds, ULONG nIpts)
{
    for ( size_t i = 0; i < nIpts; i++ )
    {
        HWND ipt = GetDlgItem(hDlg, iptIds[i]);
        SendMessageA(ipt, EM_SETREADONLY, TRUE, NULL);
        // disable tab stop ??
    }
}

VOID BasicDialog::disableButtons(HWND hDlg, ULONG* iptIds, ULONG nIpts)
{
    for ( size_t i = 0; i < nIpts; i++ )
    {
        HWND ipt = GetDlgItem(hDlg, iptIds[i]);
        EnableWindow(ipt, FALSE);
    }
}

VOID BasicDialog::setMainWindow(HWND Wnd)
{
    this->MainWindow = Wnd;
}