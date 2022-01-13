#ifndef _DIALOGS_CONNECTION_DATA_DIALOG_H
#define _DIALOGS_CONNECTION_DATA_DIALOG_H

#include <winsock2.h> // before windows.h !!!
#include <windows.h>

#include "../Resource.h"
#include "../../values.h"
#include "../ConfigFile.h"
#include "../../utils/ConfigFileParser.h"
#include "BasicDialog.h"



class ConnectionDataDialog : public BasicDialog
{
    private:
        bool disabled = false;

        BOOL has_changed = false;

        std::vector<ULONG> iptIds = { IDC_CD_IP_IPT, IDC_CD_PORT_IPT, IDC_CD_VS_IPT, IDC_CD_NAME_IPT, IDC_CD_CT_IPT };

    public:
        ConnectionDataDialog() = default;
        ~ConnectionDataDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
        
        VOID enable();

        VOID disable();
        
        BOOL hasChanged();
        
    private:
        INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;

        VOID initInputs();

        VOID fillInputs(PCONNECTION_DATA data);

        VOID updateData(PCONNECTION_DATA data);
};


#endif
