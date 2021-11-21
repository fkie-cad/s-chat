#include "FileSelector.h"

// Instance creation helper
HRESULT FileSelector::CDialogEventHandler_CreateInstance(REFIID riid, void **ppv)
{
    *ppv = NULL;
    CDialogEventHandler *pDialogEventHandler = new (std::nothrow) CDialogEventHandler();
    HRESULT hr = pDialogEventHandler ? S_OK : E_OUTOFMEMORY;
    if (SUCCEEDED(hr))
    {
        hr = pDialogEventHandler->QueryInterface(riid, ppv);
        pDialogEventHandler->Release();
    }
    return hr;
}

// Only appears after a large file has been sent.
// VERIFIER STOP 0000000000000350: pid 0x2AE8: Unloading DLL that allocated TLS index that was not freed. 
//
//    000000000047ABBA : TLS index
//    00007FFEA0AB5EE3 : Address of the code that allocated this TLS index.
//    00000207945E7FD8 : DLL name address. Use du to dump it.
//    00007FFEA0AB0000 : DLL base address.
//
// dlnashext!wil::init_once_nothrow<<lambda_ba621665f78b7b7f3bfc8a7498684c3d> >
LRESULT FileSelector::select(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix)
{
    UNREFERENCED_PARAMETER(hWnd);

    DWORD dwCookie = 0;
    BOOL bCookie = FALSE;
    DWORD dwFlags = 0;
    IShellItem *psiResult = NULL;
    PWSTR pszFilePath = NULL;
    IFileDialogEvents *pfde = NULL;
    IFileDialog *pfd = NULL;

    // CoCreate the File Open Dialog object.
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, 
                      NULL, 
                      CLSCTX_INPROC_SERVER, 
                      IID_PPV_ARGS(&pfd));
    if ( FAILED(hr) )
        return hr;

    // Create an event handling object, and hook it up to the dialog.
    hr = CDialogEventHandler_CreateInstance(IID_PPV_ARGS(&pfde));
    if ( FAILED(hr) )
        goto clean;

    // Hook up the event handler.
    hr = pfd->Advise(pfde, &dwCookie);
    if ( FAILED(hr) )
        goto clean;
    bCookie = TRUE;

    // Set the options on the dialog.
    // Before setting, always get the options first in order 
    // not to override existing options.
    hr = pfd->GetOptions(&dwFlags);
    if ( FAILED(hr) )
        goto clean;

    // In this case, get shell items only for file system items.
    hr = pfd->SetOptions(dwFlags | flags);
    if ( FAILED(hr) )
        goto clean;

    // Set the file types to display only. 
    // Notice that this is a 1-based array.
    //hr = pfd->SetFileTypes(ARRAYSIZE(c_rgSaveTypes), c_rgSaveTypes);
    //if ( FAILED(hr) )
    //    goto clean;
    // 
    // Set the selected file type index to Word Docs for this example.
    //hr = pfd->SetFileTypeIndex(INDEX_WORDDOC);
    //if ( FAILED(hr) )
    //    goto clean;
    // 
    // Set the default extension to be ".doc" file.
    //hr = pfd->SetDefaultExtension(L"doc;docx");
    //if ( FAILED(hr) )
    //    goto clean;
    
    // Show the dialog
    hr = pfd->Show(NULL);
    if ( FAILED(hr) )
        goto clean;
     
    // Obtain the result once the user clicks 
    // the 'Open' button.
    // The result is an IShellItem object.
    hr = pfd->GetResult(&psiResult);
    if ( FAILED(hr) )
        goto clean;

    // We are just going to print out the 
    // name of the file for sample sake.
    hr = psiResult->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
    if ( FAILED(hr) )
        goto clean;

    if ( output != NULL )
    {
        if ( prefix != NULL && prefix[0] != 0 )
        {
            size_t value_size = wcslen(pszFilePath)+7;
            wchar_t* value = new wchar_t[value_size];
            swprintf_s(value, value_size, L"%hs%s", prefix, pszFilePath);
            value[value_size-1] = 0;
            SetWindowTextW(output, value);
            delete[] value;
        }
        else
        {
            SetWindowTextW(output, pszFilePath);
        }
    }
    //TaskDialog(NULL,
    //           NULL,
    //           L"CommonFileDialogApp",
    //           pszFilePath,
    //           NULL,
    //           TDCBF_OK_BUTTON,
    //           TD_INFORMATION_ICON,
    //           NULL);

clean:
    if ( pszFilePath != NULL )
        CoTaskMemFree(pszFilePath);
    if ( psiResult != NULL )
        psiResult->Release();
    if ( bCookie )
        pfd->Unadvise(dwCookie);
    if ( pfde != NULL )
        pfde->Release();
    if ( pfd != NULL )
        pfd->Release();

    return hr;
}

//LRESULT SelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix)
//{
//    LRESULT r = 0;
//
//    OPENFILENAME ofn;       // common dialog box structure
//    char szFile[MAX_PATH];       // buffer for file name
//
//    // Initialize OPENFILENAME
//    ZeroMemory(&ofn, sizeof(ofn));
//    ofn.lStructSize = sizeof(ofn);
//    ofn.hwndOwner = hWnd;
//    ofn.lpstrFile = szFile;
//    // Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
//    // use the contents of szFile to initialize itself.
//    ofn.lpstrFile[0] = '\0';
//    ofn.nMaxFile = sizeof(szFile);
//    ofn.lpstrFilter = "All\0*.*\0";
//    ofn.nFilterIndex = 0;
//    ofn.lpstrFileTitle = NULL;
//    ofn.nMaxFileTitle = 0;
//    ofn.lpstrInitialDir = NULL;
//    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
//
//    (flags);
//    // Display the Open dialog box. 
//    if ( GetOpenFileName(&ofn) == TRUE )
//    {
//        if ( prefix != NULL && prefix[0] != 0 )
//        {
//            size_t value_size = strlen(ofn.lpstrFile)+7;
//            char* value = new char[value_size];
//            sprintf_s(value, value_size, "%s%s", prefix, ofn.lpstrFile);
//            value[value_size-1] = 0;
//            SetWindowTextA(output, value);
//            delete[] value;
//        }
//        else
//        {
//            SetWindowTextA(output, ofn.lpstrFile);
//        }
//    }
//
//    return r;
//}
