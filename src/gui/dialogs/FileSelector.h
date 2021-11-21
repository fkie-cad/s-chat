#ifndef _DIALOGS_FILE_SELECTOR_H
#define _DIALOGS_FILE_SELECTOR_H

#include <windows.h>

#include "CDialogEventHandler.h"




class FileSelector
{
    private:


    public:
        FileSelector() = default;
        ~FileSelector() = default;
        
        LRESULT select(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix);

    private:
        HRESULT CDialogEventHandler_CreateInstance(REFIID riid, void **ppv);
};


#endif
