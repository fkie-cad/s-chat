#pragma once

#include "resource.h"


enum class CONNECTION_STATUS { STOPPED, STOPPING, LISTENING, CONNECTED };
enum class FILE_TRANSFER_STATUS { STOPPED, ACTIVE };

#define FILE_BTN_SELECT_STR "File"
#define FILE_BTN_CANCEL_STR "Cancel"


VOID changeIcon(CONNECTION_STATUS state);

VOID toggleFileBtn(FILE_TRANSFER_STATUS state);
