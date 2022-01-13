#ifndef _DIALOGS_FILE_SELECTOR_H
#define _DIALOGS_FILE_SELECTOR_H

#include <windows.h>

#include <shobjidl.h>     // for IFileDialogEvents and IFileDialogControlEvents

//#include "CDialogEventHandler.h"




class FileSelector
{
    private:


    public:
        FileSelector() = default;
        ~FileSelector() = default;
        
        /**
         * Select a file.
         * Allocates memory for *result, be sure to free it when done with it.
         * 
         * @param hWnd HWND the parent window
         * @param flags DWORD i.e. FOS_FORCEFILESYSTEM
         * @param result PUINT8* Pointer to an buffer, will be allocated.
         * @param resultSize PULONG Pointer to an ULONG that stores the size of the buffer
         * @return HRESULT 
         */
        HRESULT select(HWND hWnd, DWORD flags, PUINT8* result, PULONG resultSize);

    private:
        //HRESULT CDialogEventHandler_CreateInstance(REFIID riid, void **ppv);
};


#endif
