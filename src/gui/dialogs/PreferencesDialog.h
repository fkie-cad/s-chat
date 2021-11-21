#ifndef _DIALOGS_PREFERENCES_DIALOG_H
#define _DIALOGS_PREFERENCES_DIALOG_H

#include <winsock2.h> // before windows.h !!!
#include <windows.h>

#include "../../values.h"
#include "../ConfigFile.h"
#include "../../utils/ConfigFileParser.h"
#include "BasicDialog.h"
#include "../Resource.h"
#include "FileSelector.h"



class PreferencesDialog : public BasicDialog
{
    private:
        PCONFIG_FILE CfgFile = nullptr;
        ConfigFileParser* CfgFileParser = nullptr;
        FileSelector FileSel;

        bool disabled = false;

        BOOL has_changed = false;

        std::vector<ULONG> iptIds = { IDC_PD_LOG_IPT, IDC_PD_CERT_IPT, IDC_PD_FILE_IPT };

    public:
        PreferencesDialog() = default;
        ~PreferencesDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
        
        VOID setConfigFile(PCONFIG_FILE CfgFile_);
        
        VOID setConfigFileParser(ConfigFileParser* CfgFileParser_);

        VOID enable();

        VOID disable();
        
        BOOL hasChanged();

    private:
        INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;

        VOID fillInputs(PPREFERENCES_DATA data);

        VOID updateData(PPREFERENCES_DATA data);
        
        VOID disableInputs(HWND hDlg);
};


#endif
