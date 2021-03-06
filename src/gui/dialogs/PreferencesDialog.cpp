#include <string>

#include "PreferencesDialog.h"
#include "../../utils/ConfigFileParser.h"
#include "../ToolTip.h"


//Message handler for connection data
INT_PTR CALLBACK PreferencesDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    BaseDlg = hDlg;
    PPREFERENCES_DATA data = (PPREFERENCES_DATA)lParam;

    switch ( message )
    {
        case WM_INITDIALOG:
            has_changed = FALSE;
            ToolTip::forChildId(IDC_PD_LOG_IPT, hDlg, "Save log files in this dir.");
            ToolTip::forChildId(IDC_PD_CERT_IPT, hDlg, "Save remote certificates in this dir.");
            ToolTip::forChildId(IDC_PD_FILE_IPT, hDlg, "Save transfered files in this dir.");
            initInputs();
            fillInputs(data);
            if ( disabled )
            {
                disableInputs(hDlg, iptIds.data(), (ULONG)iptIds.size());
                disableButtons(hDlg, btnIds.data(), (ULONG)btnIds.size());
            }
            break;

        case WM_COMMAND:
            return onCommand(hDlg, message, wParam, lParam);
            break;
    }
    return BasicDialog::openCb(hDlg, message, wParam, lParam);
}

INT_PTR PreferencesDialog::onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    INT_PTR result = 0;
    int wmId = LOWORD(wParam);
    PPREFERENCES_DATA data = (PPREFERENCES_DATA)lParam;
    HWND selTarget = NULL;
    PUINT8 path = NULL;
    ULONG pathSize = 0;

    switch ( wmId )
    {
        case IDC_PD_LOG_BTN:
            selTarget = GetDlgItem(hDlg, IDC_PD_LOG_IPT);
            result = FileSel.select(hDlg, FOS_PICKFOLDERS, &path, &pathSize);
            break;

        case IDC_PD_CERT_BTN:
            selTarget = GetDlgItem(hDlg, IDC_PD_CERT_IPT);
            result = FileSel.select(hDlg, FOS_PICKFOLDERS, &path, &pathSize);
            break;

        case IDC_PD_FILE_BTN:
            selTarget = GetDlgItem(hDlg, IDC_PD_FILE_IPT);
            result = FileSel.select(hDlg, FOS_PICKFOLDERS, &path, &pathSize);
            break;

        case IDOK:
            updateData(data);
            break;
    }

    if ( path )
    {
        SetWindowTextW(selTarget, (PWCHAR)path);
        free(path);
    }
    
    return BasicDialog::onCommand(hDlg, message, wParam, lParam);
}

VOID PreferencesDialog::initInputs()
{
    // limit input size
    HWND child = GetDlgItem(BaseDlg, IDC_PD_LOG_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(MAX_PATH-1), NULL);

    child = GetDlgItem(BaseDlg, IDC_PD_CERT_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(MAX_PATH-1), NULL);
    
    child = GetDlgItem(BaseDlg, IDC_PD_FILE_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(MAX_PATH-1), NULL);
}

VOID PreferencesDialog::fillInputs(PPREFERENCES_DATA data)
{
    SetDlgItemTextA(BaseDlg, IDC_PD_LOG_IPT, data->LogDir);
    SetDlgItemTextA(BaseDlg, IDC_PD_CERT_IPT, data->CertDir);
    SetDlgItemTextA(BaseDlg, IDC_PD_FILE_IPT, data->FileDir);
}

VOID PreferencesDialog::updateData(PPREFERENCES_DATA data)
{
    UINT len;
    CHAR tmpStr[MAX_PATH];

    len = GetDlgItemTextA(BaseDlg, IDC_PD_LOG_IPT, tmpStr, MAX_PATH);
    if ( len >= MAX_PATH )
        tmpStr[MAX_PATH-1] = 0;
    if ( strcmp(tmpStr, data->LogDir) != 0 )
    {
        strcpy_s(data->LogDir, MAX_PATH, tmpStr);
        has_changed = TRUE;
    }

    len = GetDlgItemTextA(BaseDlg, IDC_PD_CERT_IPT, tmpStr, MAX_PATH);
    if ( len >= MAX_PATH )
        tmpStr[MAX_PATH-1] = 0;
    if ( strcmp(tmpStr, data->CertDir) != 0 )
    {
        strcpy_s(data->CertDir, MAX_PATH, tmpStr);
        has_changed = TRUE;
    }

    len = GetDlgItemTextA(BaseDlg, IDC_PD_FILE_IPT, tmpStr, MAX_PATH);
    if ( len >= MAX_PATH )
        tmpStr[MAX_PATH-1] = 0;
    if ( strcmp(tmpStr, data->FileDir) != 0 )
    {
        strcpy_s(data->FileDir, MAX_PATH, tmpStr);
        has_changed = TRUE;
    }
}
        
BOOL PreferencesDialog::hasChanged()
{
    return has_changed;
}

VOID PreferencesDialog::disable()
{
    disabled = true;
}

VOID PreferencesDialog::enable()
{
    disabled = false;
}
