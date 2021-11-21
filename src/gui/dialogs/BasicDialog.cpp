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
        case IDOK:
            EndDialog(hDlg, LOWORD(wParam));
            break;
        
        case IDCANCEL:
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

// Description:
//   Creates a tooltip for an item in a dialog box. 
// Parameters:
//   idTool - identifier of an dialog box item.
//   Dlg - window handle of the dialog box.
//   Text - string to use as the tooltip text.
// Returns:
//   The handle to the tooltip.
//
HWND BasicDialog::CreateToolTip(int toolID, HWND Dlg, PCHAR Text)
{
    if ( !toolID || !Dlg || !Text )
    {
        return FALSE;
    }
    // Get the window of the tool.
    HWND hwndTool = GetDlgItem(Dlg, toolID);
    
    // Create the tooltip. g_hInst is the global instance handle.
    HWND hwndTip = CreateWindowExA(NULL, TOOLTIPS_CLASS, NULL,
                              WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              Dlg, NULL, 
                              NULL, NULL);
    
   if (!hwndTool || !hwndTip)
   {
       return (HWND)NULL;
   }                              
                              
    // Associate the tooltip with the tool.
    TOOLINFOA toolInfo = { 0 };
    toolInfo.cbSize = sizeof(toolInfo);
    toolInfo.hwnd = Dlg;
    toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    toolInfo.uId = (UINT_PTR)hwndTool;
    toolInfo.lpszText = Text;
    SendMessage(hwndTip, TTM_ADDTOOL, 0, (LPARAM)&toolInfo);

    return hwndTip;
}

// Description:
//   Creates a tooltip for a parent window
// Parameters:
//   Parent - window handle of the parent.
//   Text - string to use as the tooltip text.
// Returns:
//   void
//
void BasicDialog::CreateToolTipForWindow(HWND Parent, PCHAR Text)
{
    RECT Rect;
    GetClientRect(Parent, &Rect);
    CreateToolTipForRect(Parent, Text, &Rect); 
} 

// Description:
//   Creates a tooltip for an rectangle in a parent window
// Parameters:
//   Parent - window handle of the parent.
//   Text - string to use as the tooltip text.
//   Rect - the desired tooltip sensible rectangle
// Returns:
//   void
//
void BasicDialog::CreateToolTipForRect(HWND Parent, PCHAR Text, PRECT Rect)
{
    // Create a tooltip.
    HWND hwndTT = CreateWindowExA(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, 
                                 WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, 
                                 CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
                                 Parent, NULL, NULL, NULL);

    SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0, 
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    
    TOOLINFOA ti = { 0 };
    ti.cbSize   = sizeof(TOOLINFO);
    ti.uFlags   = TTF_SUBCLASS;
    ti.hwnd     = Parent;
    ti.hinst    = NULL;
    ti.lpszText = Text;
    
    // Set up "tool" information. In this case, the "tool" is the entire parent window.
    ti.rect.bottom = Rect->bottom;
    ti.rect.left = Rect->left;
    ti.rect.right = Rect->right;
    ti.rect.top = Rect->top;

    // Associate the tooltip with the "tool" window.
    SendMessage(hwndTT, TTM_ADDTOOL, 0, (LPARAM) (LPTOOLINFO) &ti); 
} 

VOID BasicDialog::setMainWindow(HWND Wnd)
{
    this->MainWindow = Wnd;
}