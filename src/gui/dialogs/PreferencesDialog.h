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
        FileSelector FileSel;

        bool disabled = false;

        BOOL has_changed = false;

        std::vector<ULONG> iptIds = { IDC_PD_LOG_IPT, IDC_PD_CERT_IPT, IDC_PD_FILE_IPT };
        std::vector<ULONG> btnIds = { IDC_PD_LOG_BTN, IDC_PD_CERT_BTN, IDC_PD_FILE_BTN };

    public:
        PreferencesDialog() = default;
        ~PreferencesDialog() = default;
        
        INT_PTR CALLBACK openCb(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;
        
        VOID enable();

        VOID disable();
        
        BOOL hasChanged();

    private:
        INT_PTR onCommand(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) override;

        VOID initInputs();

        VOID fillInputs(PPREFERENCES_DATA data);

        VOID updateData(PPREFERENCES_DATA data);
};


#endif
