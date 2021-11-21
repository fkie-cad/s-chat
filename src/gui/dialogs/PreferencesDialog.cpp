#include <string>

#include "PreferencesDialog.h"
#include "../../utils/ConfigFileParser.h"


//Message handler for connection data
INT_PTR CALLBACK PreferencesDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    BaseDlg = hDlg;
    PPREFERENCES_DATA data = (PPREFERENCES_DATA)lParam;

    switch ( message )
    {
        case WM_INITDIALOG:
            has_changed = FALSE;
            CreateToolTip(IDC_PD_LOG_IPT, hDlg, "Save log files in this dir.");
            CreateToolTip(IDC_PD_CERT_IPT, hDlg, "Save remote certificates in this dir.");
            CreateToolTip(IDC_PD_FILE_IPT, hDlg, "Save transfered files in this dir.");
            fillInputs(data);
            if ( disabled )
                disableInputs(hDlg);
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
    HWND selTarget;

    switch ( wmId )
    {
        case IDC_PD_LOG_BTN:
            selTarget = GetDlgItem(hDlg, IDC_PD_LOG_IPT);
            result = FileSel.select(hDlg, FOS_PICKFOLDERS, selTarget, NULL);
            break;

        case IDC_PD_CERT_BTN:
            selTarget = GetDlgItem(hDlg, IDC_PD_CERT_IPT);
            result = FileSel.select(hDlg, FOS_PICKFOLDERS, selTarget, NULL);
            break;

        case IDC_PD_FILE_BTN:
            selTarget = GetDlgItem(hDlg, IDC_PD_FILE_IPT);
            result = FileSel.select(hDlg, FOS_PICKFOLDERS, selTarget, NULL);
            break;

        case IDOK:
            updateData(data);
            break;
    }
    
    return BasicDialog::onCommand(hDlg, message, wParam, lParam);
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

VOID PreferencesDialog::disableInputs(HWND hDlg)
{
    for ( size_t i = 0; i < iptIds.size(); i++ )
    {
        HWND ipt = GetDlgItem(hDlg, iptIds[i]);
        SendMessageA(ipt, EM_SETREADONLY, TRUE, NULL);
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

VOID PreferencesDialog::setConfigFile(PCONFIG_FILE CfgFile_)
{
    this->CfgFile = CfgFile_;
}

VOID PreferencesDialog::setConfigFileParser(ConfigFileParser* CfgFileParser_)
{
    this->CfgFileParser = CfgFileParser_;
}
