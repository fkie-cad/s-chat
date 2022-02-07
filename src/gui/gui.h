#pragma once

#include "resource.h"


enum class CONNECTION_STATUS { STOPPED, STOPPING, LISTENING, CONNECTED };
enum class FILE_TRANSFER_STATUS { STOPPED, ACTIVE };


#ifndef FORMATED_TIME_STAMP_SIZE
#define FORMATED_TIME_STAMP_SIZE (0x20)
#endif

#define MSG_OPT_TH (0.9)
#define MSG_OPT_CLR (0.2)



VOID changeIcon(CONNECTION_STATUS state);

VOID toggleFileBtn(FILE_TRANSFER_STATUS state);
