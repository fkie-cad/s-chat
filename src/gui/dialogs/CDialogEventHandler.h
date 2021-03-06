#ifndef CDIALOG_EVENT_HANDLER_H
#define CDIALOG_EVENT_HANDLER_H

#include <windows.h>
#include <shlobj.h>
#include <objbase.h>      // For COM headers
#include <shobjidl.h>     // for IFileDialogEvents and IFileDialogControlEvents
#include <shlwapi.h>
#include <knownfolders.h> // for KnownFolder APIs/datatypes/function headers
#include <propvarutil.h>  // for PROPVAR-related functions
#include <propkey.h>      // for the Property key APIs/datatypes
#include <propidl.h>      // for the Property System APIs
#include <strsafe.h>      // for StringCchPrintfW
#include <shtypes.h>      // for COMDLG_FILTERSPEC
#include <new>

//const COMDLG_FILTERSPEC c_rgSaveTypes[] =
//{
//    {L"Word Document (*.doc)",       L"*.doc"},
//    {L"Web Page (*.htm; *.html)",    L"*.htm;*.html"},
//    {L"Text Document (*.txt)",       L"*.txt"},
//    {L"All Documents (*.*)",         L"*.*"}
//};

// Indices of file types
#define INDEX_WORDDOC 1
#define INDEX_WEBPAGE 2
#define INDEX_TEXTDOC 3

// Controls
#define CONTROL_GROUP           2000
#define CONTROL_RADIOBUTTONLIST 2
#define CONTROL_RADIOBUTTON1    1
#define CONTROL_RADIOBUTTON2    2       // It is OK for this to have the same ID as CONTROL_RADIOBUTTONLIST,
                                        // because it is a child control under CONTROL_RADIOBUTTONLIST

// IDs for the Task Dialog Buttons
#define IDC_BASICFILEOPEN                       100
#define IDC_ADDITEMSTOCUSTOMPLACES              101
#define IDC_ADDCUSTOMCONTROLS                   102
#define IDC_SETDEFAULTVALUESFORPROPERTIES       103
#define IDC_WRITEPROPERTIESUSINGHANDLERS        104
#define IDC_WRITEPROPERTIESWITHOUTUSINGHANDLERS 105

class CDialogEventHandler : public IFileDialogEvents,
                            public IFileDialogControlEvents
{
    public:
        // IUnknown methods
        IFACEMETHODIMP QueryInterface(REFIID riid, void** ppv);

        IFACEMETHODIMP_(ULONG) AddRef();

        IFACEMETHODIMP_(ULONG) Release();

        // IFileDialogEvents methods
        IFACEMETHODIMP OnFileOk(IFileDialog *) { return S_OK; };
        IFACEMETHODIMP OnFolderChange(IFileDialog *) { return S_OK; };
        IFACEMETHODIMP OnFolderChanging(IFileDialog *, IShellItem *) { return S_OK; };
        IFACEMETHODIMP OnHelp(IFileDialog *) { return S_OK; };
        IFACEMETHODIMP OnSelectionChange(IFileDialog *) { return S_OK; };
        IFACEMETHODIMP OnShareViolation(IFileDialog *, IShellItem *, FDE_SHAREVIOLATION_RESPONSE *) { return S_OK; };
        IFACEMETHODIMP OnTypeChange(IFileDialog *pfd);
        IFACEMETHODIMP OnOverwrite(IFileDialog *, IShellItem *, FDE_OVERWRITE_RESPONSE *) { return S_OK; };

        // IFileDialogControlEvents methods
        IFACEMETHODIMP OnItemSelected(IFileDialogCustomize *pfdc, DWORD dwIDCtl, DWORD dwIDItem);
        IFACEMETHODIMP OnButtonClicked(IFileDialogCustomize *, DWORD) { return S_OK; };
        IFACEMETHODIMP OnCheckButtonToggled(IFileDialogCustomize *, DWORD, BOOL) { return S_OK; };
        IFACEMETHODIMP OnControlActivating(IFileDialogCustomize *, DWORD) { return S_OK; };

        CDialogEventHandler();
        
    private:
        ~CDialogEventHandler();
        long _cRef;
};

#endif
