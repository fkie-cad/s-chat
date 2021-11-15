#include <string>

#include "ConnectionDataDialog.h"
#include "../Resource.h"
#include "../../utils/ConfigFileParser.h"



//Message handler for connection data
INT_PTR CALLBACK ConnectionDataDialog::openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    Dlg = hDlg;
    PCONNECTION_DATA data = (PCONNECTION_DATA)lParam;

    switch ( message )
    {
    case WM_INITDIALOG:
        fillInputs(data);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if ( LOWORD(wParam) == IDOK )
        {
            updateData(data);
            //updateConfigFile(data);
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        if ( LOWORD(wParam) == IDCANCEL )
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

VOID ConnectionDataDialog::fillInputs(PCONNECTION_DATA data)
{
    SetDlgItemTextA(Dlg, IDC_CD_IP_IPT, data->ip);
    SetDlgItemTextA(Dlg, IDC_CD_PORT_IPT, data->port);
    if ( data->family == AF_INET )
        SetDlgItemTextA(Dlg, IDC_CD_VS_IPT, "4");
    else if ( data->family == AF_INET6 )
        SetDlgItemTextA(Dlg, IDC_CD_VS_IPT, "6");
    else
        SetDlgItemTextA(Dlg, IDC_CD_VS_IPT, "");
    SetDlgItemTextA(Dlg, IDC_CD_NAME_IPT, data->name);
    SetDlgItemTextA(Dlg, IDC_CD_CT_IPT, data->CertThumb);
}

VOID ConnectionDataDialog::updateData(PCONNECTION_DATA data)
{
    UINT len;

    len = GetDlgItemTextA(Dlg, IDC_CD_IP_IPT, data->ip, MAX_IP_LN);
    if ( len >= MAX_IP_LN )
        data->ip[MAX_IP_LN-1] = 0;

    if ( data->ip[0] != 0 )
    {
        char* ptr = strstr(data->ip, ".");
        if ( ptr != NULL )
            data->family = AF_INET;
        ptr = strstr(data->ip, ":");
        if ( ptr != NULL )
            data->family = AF_INET6;
    }
    else
    {
        char ipv_str[2];
        len = GetDlgItemTextA(Dlg, IDC_CD_VS_IPT, ipv_str, 2);
        if ( len >= 2 )
            ipv_str[1] = 0;
        int ipv = (int)strtoul(ipv_str, NULL, 0);
        if ( ipv == 4 )
            data->family = AF_INET;
        else if ( ipv == 6 )
            data->family = AF_INET6;
    }

    len = GetDlgItemTextA(Dlg, IDC_CD_PORT_IPT, data->port, MAX_PORT_LN);
    if ( len >= MAX_PORT_LN )
        data->port[MAX_PORT_LN-1] = 0;

    len = GetDlgItemTextA(Dlg, IDC_CD_NAME_IPT, data->name, MAX_NAME_LN);
    if ( len >= MAX_NAME_LN )
        data->name[MAX_NAME_LN-1] = 0;

    len = GetDlgItemTextA(Dlg, IDC_CD_CT_IPT, data->CertThumb, SHA1_STRING_BUFFER_LN);
    if ( len >= SHA1_STRING_BUFFER_LN )
        data->CertThumb[SHA1_STRING_BUFFER_LN-1] = 0;
}

//VOID ConnectionDataDialog::updateConfigFile(PCONNECTION_DATA data)
//{
//    std::string tmpStr;
//    uint16_t tmpShrt;
//
//    tmpStr = CfgFileParser->getStringValue(CfgFile->Keys[CONFIG_FILE_KEY_IP], MAX_IP_LN-1, "");
//    if ( tmpStr != data->ip )
//    {
//        CfgFileParser->setStringValue(CfgFile->Keys[CONFIG_FILE_KEY_IP], data->ip, strlen(data->ip));
//    }
//
//    tmpStr = CfgFileParser->getStringValue(CfgFile->Keys[CONFIG_FILE_KEY_PORT], MAX_PORT_LN-1, "");
//    if ( tmpStr != data->port )
//    {
//        CfgFileParser->setStringValue(CfgFile->Keys[CONFIG_FILE_KEY_PORT], data->port, strlen(data->port));
//    }
//
//    tmpShrt = CfgFileParser->getUInt16Value(CfgFile->Keys[CONFIG_FILE_KEY_IP_VS], AF_UNSPEC);
//    if ( tmpShrt == 4 )
//        tmpShrt = AF_INET;
//    else if ( tmpShrt == 4 )
//        tmpShrt = AF_INET6;
//    if ( tmpShrt != data->family )
//    {
//        if ( tmpShrt == AF_INET )
//            tmpShrt = 4;
//        else if ( tmpShrt == AF_INET6 )
//            tmpShrt = 6;
//        else
//            tmpShrt = 0;
//
//        CfgFileParser->setUInt16Value(CfgFile->Keys[CONFIG_FILE_KEY_IP_VS], tmpShrt);
//    }
//
//    tmpStr = CfgFileParser->getStringValue(CfgFile->Keys[CONFIG_FILE_KEY_USER_NAME], MAX_NAME_LN-1, "");
//    if ( tmpStr != data->name )
//    {
//        CfgFileParser->setStringValue(CfgFile->Keys[CONFIG_FILE_KEY_USER_NAME], data->name, strlen(data->name));
//    }
//
//    tmpStr = CfgFileParser->getStringValue(CfgFile->Keys[CONFIG_FILE_KEY_CERT_THUMB], SHA1_STRING_BUFFER_LN-1, "");
//    if ( tmpStr != data->CertThumb )
//    {
//        CfgFileParser->setStringValue(CfgFile->Keys[CONFIG_FILE_KEY_CERT_THUMB], data->CertThumb, strlen(data->CertThumb));
//    }
//}

VOID ConnectionDataDialog::setConfigFile(PCONFIG_FILE CfgFile_)
{
    this->CfgFile = CfgFile_;
}

VOID ConnectionDataDialog::setConfigFileParser(ConfigFileParser* CfgFileParser_)
{
    this->CfgFileParser = CfgFileParser_;
}
