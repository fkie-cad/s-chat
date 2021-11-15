#ifndef _DIALOGS_CONNECTION_DATA_DIALOG_H
#define _DIALOGS_CONNECTION_DATA_DIALOG_H

#include <winsock2.h> // before windows.h !!!
#include <windows.h>

#include "../../values.h"
#include "../ConfigFile.h"
#include "../../utils/ConfigFileParser.h"



class ConnectionDataDialog
{
    private:
        HWND Dlg = nullptr;
        PCONFIG_FILE CfgFile = nullptr;
        ConfigFileParser* CfgFileParser = nullptr;

    public:
        ConnectionDataDialog() = default;
        ~ConnectionDataDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
        
        VOID setConfigFile(PCONFIG_FILE CfgFile_);
        
        VOID setConfigFileParser(ConfigFileParser* CfgFileParser_);

    private:
        VOID fillInputs(PCONNECTION_DATA data);

        VOID ConnectionDataDialog::updateData(PCONNECTION_DATA data);
        
        //VOID ConnectionDataDialog::updateConfigFile(PCONNECTION_DATA data);
};


#endif
