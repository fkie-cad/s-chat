#ifndef _DIALOGS_ABOUT_DIALOG_H
#define _DIALOGS_ABOUT_DIALOG_H

#include <windows.h>


#include "../Resource.h"
#include "BasicDialog.h"



typedef struct _ABOUT_DIALOG_PARAMS {
    const char* BinaryName;
    const char* ActVersion;
    const char* LastChanged;
    const char* CompileDate;
    const char* CompileTime;
} ABOUT_DIALOG_PARAMS, *PABOUT_DIALOG_PARAMS;


class AboutDialog : public BasicDialog
{
    private:

    public:
        AboutDialog() = default;
        ~AboutDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
        
    private:
        VOID fillInputs(LPARAM lParam);

        INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
};


#endif
