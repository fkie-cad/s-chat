#ifndef _DIALOGS_CONNECTION_DATA_DIALOG_H
#define _DIALOGS_CONNECTION_DATA_DIALOG_H

#include <windows.h>


class ConnectionDataDialog
{
    private:

    public:
        ConnectionDataDialog() = default;
        ~ConnectionDataDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
};


#endif
