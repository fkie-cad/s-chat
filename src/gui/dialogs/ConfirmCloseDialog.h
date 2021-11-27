#ifndef _DIALOGS_CONFIRM_CLOSE_DIALOG_H
#define _DIALOGS_CONFIRM_CLOSE_DIALOG_H

#include <windows.h>


#include "../Resource.h"
#include "BasicDialog.h"



class ConfirmCloseDialog : public BasicDialog
{
    private:

    public:
        ConfirmCloseDialog() = default;
        ~ConfirmCloseDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
        
    private:
        VOID fillInputs(LPARAM lParam);

        INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
};


#endif
