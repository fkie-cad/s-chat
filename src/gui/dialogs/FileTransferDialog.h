#ifndef _DIALOGS_FILE_TRANSFER_DIALOG_H
#define _DIALOGS_FILE_TRANSFER_DIALOG_H

#include <windows.h>

#include "BasicDialog.h"
#include "../Resource.h"



class FileTransferDialog : public BasicDialog
{
    private:

    public:
        FileTransferDialog() = default;
        ~FileTransferDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
        
    private:
        INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;

        VOID fillInputs(PCHAR BaseName);
};


#endif
