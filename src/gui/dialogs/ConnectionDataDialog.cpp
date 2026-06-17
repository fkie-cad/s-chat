#include <string>

#include "ConnectionDataDialog.h"
#include "../../utils/ConfigFileParser.h"
#include "../ToolTip.h"
#include "../controlls/subEditControl.h"

 #define TT_CD_IP                    "Server Ip. The Server may leave this empty."
 #define TT_CD_PORT                  "Server/Listening Port"
 #define TT_CD_IPVS                  "Ip version 4 or 6. Can be left empty, if Ip is filled."
 #define TT_CD_NICK                  "Your nick name appearing in the chat."
 #define TT_CD_TP                    "Thumbprint (sha1) of your certificate."

//Message handler for connection data
INT_PTR CALLBACK ConnectionDataDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    BaseDlg = hDlg;
    PCONNECTION_DATA data = (PCONNECTION_DATA)lParam;

    switch ( message )
    {
        case WM_INITDIALOG:
            has_changed = FALSE;

            ToolTip::forChildId(IDC_CD_IP_IPT, hDlg, TT_CD_IP);
            ToolTip::forChildId(IDC_CD_PORT_IPT, hDlg, TT_CD_PORT);
            ToolTip::forChildId(IDC_CD_VS_IPT, hDlg, TT_CD_IPVS);
            ToolTip::forChildId(IDC_CD_NAME_IPT, hDlg, TT_CD_NICK);
            ToolTip::forChildId(IDC_CD_CT_IPT, hDlg, TT_CD_TP);

            initInputs();
            fillInputs(data);
            if ( disabled )
                disableInputs(hDlg, iptIds.data(), (ULONG)iptIds.size());
            break;

        case WM_COMMAND:
            return onCommand(hDlg, message, wParam, lParam);
            break;
    }
    return BasicDialog::openCb(hDlg, message, wParam, lParam);
}

INT_PTR ConnectionDataDialog::onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    int wmId = LOWORD(wParam);
    PCONNECTION_DATA data = (PCONNECTION_DATA)lParam;

    switch ( wmId )
    {
        case IDOK:
            updateData(data);
            break;
    }
    
    return BasicDialog::onCommand(hDlg, message, wParam, lParam);
}

VOID ConnectionDataDialog::initInputs()
{
    // limit input size
    HWND child = GetDlgItem(BaseDlg, IDC_CD_IP_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(MAX_IP_STR_LN-1), NULL);
	SetWindowSubclass(child, IpEditControl, IDC_CD_IP_IPT, 0);

    child = GetDlgItem(BaseDlg, IDC_CD_PORT_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(MAX_PORT_STR_LN-1), NULL);
    
    child = GetDlgItem(BaseDlg, IDC_CD_VS_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(1), NULL);
    
    child = GetDlgItem(BaseDlg, IDC_CD_NAME_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(MAX_NAME_LN-1), NULL);

    child = GetDlgItem(BaseDlg, IDC_CD_CT_IPT);
    SendMessageA(child, EM_SETLIMITTEXT, (WPARAM)(SHA1_STRING_LN), NULL);
    SetWindowSubclass(child, HexEditControl, IDC_CD_CT_IPT, 0);
}

VOID ConnectionDataDialog::fillInputs(PCONNECTION_DATA data)
{
    SetDlgItemTextA(BaseDlg, IDC_CD_IP_IPT, data->ip);
    SetDlgItemTextA(BaseDlg, IDC_CD_PORT_IPT, data->port);
    if ( data->family == AF_INET )
        SetDlgItemTextA(BaseDlg, IDC_CD_VS_IPT, "4");
    else if ( data->family == AF_INET6 )
        SetDlgItemTextA(BaseDlg, IDC_CD_VS_IPT, "6");
    else
        SetDlgItemTextA(BaseDlg, IDC_CD_VS_IPT, "");
    SetDlgItemTextA(BaseDlg, IDC_CD_NAME_IPT, data->name);
    SetDlgItemTextA(BaseDlg, IDC_CD_CT_IPT, data->CertThumb);
}

VOID ConnectionDataDialog::updateData(PCONNECTION_DATA data)
{
    UINT len;
    CHAR tmpStr[MAX_PATH];
    USHORT tmpShrt;

    len = GetDlgItemTextA(BaseDlg, IDC_CD_IP_IPT, tmpStr, MAX_IP_STR_LN);
    if ( len >= MAX_IP_STR_LN )
        tmpStr[MAX_IP_STR_LN-1] = 0;
    if ( strcmp(tmpStr, data->ip) != 0 )
    {
        strcpy_s(data->ip, MAX_IP_STR_LN, tmpStr);
        has_changed = TRUE;
    }

    if ( data->ip[0] != 0 )
    {
        tmpShrt = AF_UNSPEC;
        char* ptr = strstr(data->ip, ".");
        if ( ptr != NULL )
            tmpShrt = AF_INET;
        ptr = strstr(data->ip, ":");
        if ( ptr != NULL )
            tmpShrt = AF_INET6;

        if ( tmpShrt != data->family )
        {
            data->family = tmpShrt;
            has_changed = TRUE;
        }
    }
    else
    {
        len = GetDlgItemTextA(BaseDlg, IDC_CD_VS_IPT, tmpStr, 2);
        if ( len >= 2 )
            tmpStr[1] = 0;
        tmpShrt = (USHORT)strtoul(tmpStr, NULL, 0);
        if ( tmpShrt == 4 )
            tmpShrt = AF_INET;
        else if ( tmpShrt == 6 )
            tmpShrt = AF_INET6;
        else
            tmpShrt = AF_UNSPEC;

        if ( tmpShrt != data->family )
        {
            data->family = tmpShrt;
            has_changed = TRUE;
        }
    }

    len = GetDlgItemTextA(BaseDlg, IDC_CD_PORT_IPT, tmpStr, MAX_PORT_STR_LN);
    if ( len >= MAX_PORT_STR_LN )
        tmpStr[MAX_PORT_STR_LN-1] = 0;
    if ( strcmp(tmpStr, data->port) != 0 )
    {
        strcpy_s(data->port, MAX_PORT_STR_LN, tmpStr);
        has_changed = TRUE;
    }

    len = GetDlgItemTextA(BaseDlg, IDC_CD_NAME_IPT, tmpStr, MAX_NAME_LN);
    if ( len >= MAX_NAME_LN )
        tmpStr[MAX_NAME_LN-1] = 0;
    if ( strcmp(tmpStr, data->name) != 0 )
    {
        strcpy_s(data->name, MAX_NAME_LN, tmpStr);
        has_changed = TRUE;
    }

    len = GetDlgItemTextA(BaseDlg, IDC_CD_CT_IPT, tmpStr, SHA1_STRING_BUFFER_LN);
    if ( len >= SHA1_STRING_BUFFER_LN )
        tmpStr[SHA1_STRING_BUFFER_LN-1] = 0;
    if ( strcmp(tmpStr, data->CertThumb) != 0 )
    {
        strcpy_s(data->CertThumb, SHA1_STRING_BUFFER_LN, tmpStr);
        has_changed = TRUE;
    }
}
        
BOOL ConnectionDataDialog::hasChanged()
{
    return has_changed;
}

VOID ConnectionDataDialog::disable()
{
    disabled = true;
}

VOID ConnectionDataDialog::enable()
{
    disabled = false;
}
