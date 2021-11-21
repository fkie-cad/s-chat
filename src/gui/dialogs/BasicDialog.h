#ifndef _DIALOGS_BASIC_DIALOG_H
#define _DIALOGS_BASIC_DIALOG_H

#include <windows.h>



class BasicDialog
{
    protected:
        HWND BaseDlg = nullptr;
        HWND MainWindow = nullptr;
        RECT DlgRect;
        RECT MainWindowRect;

    public:
        BasicDialog() = default;
        virtual ~BasicDialog() = default;
        
        virtual INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
        
        VOID setMainWindow(HWND Wnd);

    protected:
        virtual INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
        
        VOID centerDialog(HWND hDlg);

        HWND CreateToolTip(int toolID, HWND Dlg, PCHAR Text);
        void CreateToolTipForWindow(HWND Parent, PCHAR Text);
        void CreateToolTipForRect(HWND Parent, PCHAR Text, PRECT Rect);

    private:
};


#endif
