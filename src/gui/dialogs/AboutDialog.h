#ifndef _DIALOGS_ABOUT_DIALOG_H
#define _DIALOGS_ABOUT_DIALOG_H

#include <windows.h>


#include "../Resource.h"
#include "BasicDialog.h"



class AboutDialog : public BasicDialog
{
    private:

    public:
        AboutDialog() = default;
        ~AboutDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
        
    private:
        VOID fillInputs();

        INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
};


#endif
