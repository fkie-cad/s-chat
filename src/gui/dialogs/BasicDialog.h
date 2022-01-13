#ifndef _DIALOGS_BASIC_DIALOG_H
#define _DIALOGS_BASIC_DIALOG_H

#include <windows.h>



class BasicDialog
{
    protected:
        HWND BaseDlg = nullptr;
        HWND MainWindow = nullptr;
        RECT DlgRect = {};
        RECT MainWindowRect = {};

    public:
        BasicDialog() = default;
        virtual ~BasicDialog() = default;
        
        virtual INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
        
        VOID setMainWindow(HWND Wnd);

    protected:
        virtual INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
        
        VOID centerDialog(HWND hDlg);

        VOID disableInputs(HWND hDlg, ULONG* iptIds, ULONG nIpts);

        VOID disableButtons(HWND hDlg, ULONG* iptIds, ULONG nIpts);

    private:
};


#endif
