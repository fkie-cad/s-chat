#ifdef _DEBUG
#pragma warning( disable : 4100 4101 4102 4189 )
#endif

#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "framework.h"
#include <Commdlg.h>
#include <shobjidl.h>

#include "gui.h"

#include <mutex>
#include <string>
#include <vector>

#include "../dbg.h"
#include "helper.h"
#include "../values.h"
#include "../version.h"
#include "../engine/engine.h"
#include "../guiBridge.h"
#include "../files/Files.h"
#include "../Strings.h"

#include "../utils/ConfigFileParser.h"

#include "dialogs/AboutDialog.h"
#include "dialogs/BasicDialog.h"
#include "dialogs/ConfirmCloseDialog.h"
#include "dialogs/ConnectionDataDialog.h"
#include "dialogs/PreferencesDialog.h"
#include "dialogs/FileTransferDialog.h"
#include "dialogs/FileSelector.h"
#include "ToolTip.h"
#include "ConfigFile.h"

#define MAX_LOADSTRING (0x80)

#define ANONYMOUS ""
#define DEFAULT_IP4 ""
#define DEFAULT_IP6 ""
#define DEFAULT_PORT ""

#define MSG_CMD_FILE "\\file "
#define MSG_CMD_FILE_LN (strlen(MSG_CMD_FILE))



// Forward declarations of functions included in this code module:
static ATOM MyRegisterClass(HINSTANCE hInstance);
static BOOL InitInstance(HINSTANCE, int);
static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

static INT_PTR CALLBACK AboutDialogCB(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK PrefsDialogCB(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK ConnectionDataDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK FTAcceptDialog(HWND, UINT, WPARAM, LPARAM);
static INT ConfirmClose(HWND hWnd);
static INT_PTR CALLBACK onCloseCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

static LRESULT onCommand(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
static LRESULT onCreate(HWND hWnd);
static LRESULT onPaint(HWND hWnd);
//static LRESULT onClose(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
static LRESULT onDestroy(HWND hWnd);
static LRESULT onSafeData();

static LRESULT onSelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix);
static LRESULT SelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix);

static LRESULT onConnect(HWND hWnd);
static LRESULT onListen(HWND hWnd);
static LRESULT onSend(HWND hWnd);
static VOID stopNetworking();
static DWORD WINAPI ReceiveThreadFn(LPVOID lpParam);
static DWORD WINAPI ListenThread(LPVOID lpParam);

static VOID parseCmdLine(LPSTR lpCmdLine);
static void parseConfigFile();
static void fillParamDefaults();
static VOID updateConfigFile(PCONNECTION_DATA ConnData, PPREFERENCES_DATA PrefsData);

static VOID sayHello();
static VOID setupNetClient();
static VOID stopConnection(HWND hWnd, const char* msg, HWND btn, const char* btnText, HWND otherBtn);
static BOOL loadSound(LPSTR lpName, HGLOBAL* Res);
static LRESULT sendMessage(PCHAR msg, ULONG msg_len);
static LRESULT sendFile(PCHAR msg, ULONG msg_len);
static LRESULT CancelFileTransfer();

DWORD WINAPI InfoStatusFade(LPVOID lpParam);



// Global Variables:
HWND MainWindow;
HINSTANCE MainInstance;                                // current instance
static CHAR WindowTitleD[MAX_LOADSTRING];                  // The title bar default text
static CHAR WindowTitleC[MAX_LOADSTRING];                  // The title bar changed text
static CONST CHAR* WindowTitle = NULL;                  // The title bar text
static CHAR WindowClass[MAX_LOADSTRING];            // the main window class name

static HWND MessageIpt, MessageOpt, ListenBtn, ConnectBtn, SendBtn;
static HWND ConnStatusOpt, InfoStatusOpt;
//HWND NameIpt, IpIpt, IpVersionIpt, PortIpt, CertFileIpt;
//HWND FileIpt, ShaOpt;
static HWND SelFileBtn;
HWND FilePBar;

#define ERROR_MESSAGE_SIZE (0x200)
static CHAR err_msg[ERROR_MESSAGE_SIZE];

//#define WND_NAME_IPT_IDX           (0x1)
//#define WND_IP_IPT_IDX             (0x2)
//#define WND_PORT_IPT_IDX           (0x3)
//#define WND_CERT_IPT_IDX           (0x4)
#define WND_INFO_STATUS_OPT_IDX    (0x5)
#define WND_MESSAGE_IPT_IDX        (0x6)
#define WND_MESSAGE_OPT_IDX        (0x7)
#define WND_CONNECT_BTN_IDX        (0x8)
#define WND_LISTEN_BTN_IDX         (0x9)
#define WND_STATUS_OPT_IDX         (0xa)
#define WND_SEND_BTN_IDX           (0xb)
#define WND_FILE_PROGRESS_IDX      (0xc)
#define WND_IP_VERSION_IPT_IDX     (0xd)
#define WND_FILE_IPT_IDX           (0xe)
#define WND_FILE_BTN_IDX           (0xf)

static CONNECTION_STATUS ConnectionStatus = CONNECTION_STATUS::STOPPED;
static FILE_TRANSFER_STATUS FileTransferStatus = FILE_TRANSFER_STATUS::STOPPED;
std::mutex cstmtx;
static ULONG ConnectionThreadId = 0;
static HANDLE ConnectionThread = NULL;


extern ADDRESS_FAMILY family;

static char* pmsg = NULL;
static int type = 0;


static HICON gui_icon_on = NULL;
static HICON gui_icon_off = NULL;
static HICON gui_icon_listen = NULL;

HGLOBAL notify_snd = NULL; 

CONFIG_FILE CfgFile;
ConfigFileParser* CfgFileParser = nullptr;

BOOL DataHasChanged = FALSE;

PREFERENCES_DATA PreferencesData;
PreferencesDialog PreferencesDlg;

CONNECTION_DATA ConnectionData;
ConnectionDataDialog ConnectionDataDlg;

ConfirmCloseDialog CloseDlg;
AboutDialog AboutDlg;
FileTransferDialog FileTransferDlg;

FileSelector FileSel;

#define DEFAULT_WINDOW_WIDTH (800)
#define DEFAULT_WINDOW_HEIGHT (530)
#define MIN_WINDOW_WIDTH (600)
#define MIN_WINDOW_HEIGHT (260)
#define BTN_W (100)
#define BTN_H (20)
#define PARENT_PADDING (10)
#define IPT_MARGIN (10)
#define IPT_H (20)
#define DEFAULT_PROG_BAR_W (100)
#define DEFAULT_PROG_BAR_H (20)
#define STATUS_OPT_W (200)
#define STATUS_MARGIN (1)

RECT MainRect;
RECT MessageOptRect;
RECT MessageIptRect;
RECT StatusOptRect;
RECT InfoStatusOptRect;

int rows_y[] = { 10, 30, 50, 70, 100, 130, 370, 400, 430 };




int APIENTRY WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nCmdShow
)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

    ZeroMemory(&PreferencesData, sizeof(PREFERENCES_DATA));
    ZeroMemory(&ConnectionData, sizeof(CONNECTION_DATA));
    
    CfgFile.init();
    CfgFileParser = new ConfigFileParser(CfgFile.Keys, '#');

    parseCmdLine(lpCmdLine);
    parseConfigFile();
    fillParamDefaults();


    // load icons
    gui_icon_on = (HICON)LoadImageA(hInstance, MAKEINTRESOURCEA(IDI_GUI_ON), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    gui_icon_off = (HICON)LoadImageA(hInstance, MAKEINTRESOURCEA(IDI_GUI_OFF), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);
    gui_icon_listen = (HICON)LoadImageA(hInstance, MAKEINTRESOURCEA(IDI_GUI_LISTEN), IMAGE_ICON, 0, 0, LR_DEFAULTSIZE);

    if ( !gui_icon_on || !gui_icon_off || !gui_icon_listen )
    {
        return 0;
    }

    // load sounds
    if ( !loadSound(MAKEINTRESOURCEA(IDW_NOTIFY), &notify_snd) )
        notify_snd = NULL;

    // Initialize global strings
    int ln = LoadStringA(hInstance, IDS_APP_TITLE, WindowTitleD, MAX_LOADSTRING);
    if ( ln >= MAX_LOADSTRING )
        WindowTitleD[MAX_LOADSTRING-1] = 0;
    strcpy_s(WindowTitleC, MAX_LOADSTRING, WindowTitleD);
    if ( ln >= MAX_LOADSTRING-1 )
    {
        WindowTitleC[MAX_LOADSTRING-2] = '*';
        WindowTitleC[MAX_LOADSTRING-1] = 0;
    }
    else
    {
        WindowTitleC[ln] = '*';
        WindowTitleC[ln+1] = 0;
    }
    WindowTitle = WindowTitleD;

    LoadStringA(hInstance, IDC_GUI, WindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if ( !InitInstance(hInstance, nCmdShow) )
    {
        return 0;
    }
    
    ConnectionDataDlg.setConfigFile(&CfgFile);
    ConnectionDataDlg.setMainWindow(MainWindow);
    
    PreferencesDlg.setMainWindow(MainWindow);
    PreferencesDlg.setConfigFile(&CfgFile);

    AboutDlg.setMainWindow(MainWindow);

    CloseDlg.setMainWindow(MainWindow);

    FileTransferDlg.setMainWindow(MainWindow);


    HACCEL hAccelTable = LoadAcceleratorsA(hInstance, MAKEINTRESOURCEA(IDC_GUI));

    MSG msg;

    // Main message loop:
    while ( GetMessageA(&msg, nullptr, 0, 0) )
    {
        if ( !TranslateAcceleratorA(msg.hwnd, hAccelTable, &msg) )
        {
            TranslateMessage(&msg);
            DispatchMessageA(&msg);
        }
    }

    return (int)msg.wParam;
}

VOID parseCmdLine(LPSTR lpCmdLine)
{
    PCHAR* argv = NULL;
    INT argc = 0;

    argv = CommandLineToArgvA(lpCmdLine, &argc);
    if ( argv == NULL )
    {
        return;
    }

    ZeroMemory(ConnectionData.ip, MAX_IP_LN);
    ZeroMemory(ConnectionData.port, MAX_PORT_LN);
    ZeroMemory(ConnectionData.name, MAX_NAME_LN);
    ZeroMemory(ConnectionData.CertThumb, SHA1_STRING_BUFFER_LN);

    ZeroMemory(PreferencesData.LogDir, MAX_PATH);
    ZeroMemory(PreferencesData.CertDir, MAX_PATH);
    ZeroMemory(PreferencesData.FileDir, MAX_PATH);

    int i;
    char iOption = NULL;
    char* pszOption = NULL;
    size_t pszOptionLen = 0;
    int ipv;

    for ( i = 0; i < argc; i++ ) 
    {
        if(argv[i][0] == '/') argv[i][0] = '-';

        if(argv[i][0] != '-') 
        {
            printf("Invalid argument \"%s\"\n", argv[i]);
            continue;
        }

        iOption = argv[i][1];
        if ( i < argc-1 )
        {
            pszOption = argv[i+1];
            pszOptionLen = strlen(pszOption);
        }
        else
        {
            pszOption = NULL;
            pszOptionLen = 0;
        }

        switch(iOption) 
        {
        case 'c':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < SHA1_STRING_BUFFER_LN ) 
                //strcpy_s(CertFile, MAX_PATH, pszOption);
                strcpy_s(ConnectionData.CertThumb, SHA1_STRING_BUFFER_LN, pszOption);

            i++;
            break;

        case 'd':
            if ( pszOption == NULL )
                break;
            
            if ( pszOptionLen < MAX_PATH )
                strcpy_s(PreferencesData.CertDir, MAX_PATH, pszOption);

            i++;
            break;

        case 'f':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_PATH ) 
                strcpy_s(PreferencesData.FileDir, MAX_PATH, pszOption);

            i++;
            break;

        case 'i':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_IP_LN ) 
                strcpy_s(ConnectionData.ip, MAX_IP_LN, pszOption);

            i++;
            break;

        case 'l':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_PATH )
                strcpy_s(PreferencesData.LogDir, MAX_PATH, pszOption);            

            i++;
            break;
            
        case 'n':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_NAME_LN ) 
                strcpy_s(ConnectionData.name, MAX_NAME_LN, pszOption);

            i++;
            break;

        case 'm':
            if ( pszOption == NULL )
                break;

            pmsg = new char[pszOptionLen+1];
            if ( pmsg )
            {
                strcpy_s(pmsg, pszOptionLen+1, pszOption);
                pmsg[pszOptionLen] = 0;
            }
            i++;
            break;

        case 'p':
            if ( pszOption == NULL )
                break;
            
            if ( pszOptionLen < MAX_PORT_LN ) 
                strcpy_s(ConnectionData.port, MAX_PORT_LN, pszOption);

            i++;
            break;

        case 't':
            if ( pszOption == NULL )
                break;
            
            type = (int)strtoul(pszOption, NULL, 0);

            i++;
            break;

        case 'v':
            if ( pszOption == NULL )
                break;
            
            ipv = (int)strtoul(pszOption, NULL, 0);
            if ( ipv == 4 )
            {
                family = AF_INET;
                ConnectionData.family = AF_INET;
            }
            else if ( ipv == 6 )
            {
                family = AF_INET6;
                ConnectionData.family = AF_INET6;
            }

            i++;
            break;

        default:
            printf("Invalid option \"%s\"\n", argv[i]);
        }
    }

    if ( argv )
        HeapFree(GetProcessHeap(), 0, argv);
}

void fillParamDefaults()
{
    if ( ConnectionData.port[0] == 0 )
        strcpy_s(ConnectionData.port, MAX_PORT_LN, DEFAULT_PORT);

    if ( ConnectionData.name[0] == 0 )
        strcpy_s(ConnectionData.name, MAX_NAME_LN, ANONYMOUS);

    if ( ConnectionData.ip[0] == 0 )
    {
        strcpy_s(ConnectionData.ip, MAX_IP_LN, DEFAULT_IP4);
    }

    if ( PreferencesData.CertDir[0] == 0 )
    {
        strcpy_s(PreferencesData.CertDir, MAX_PATH, ".\\");
    }
    else
    {
        cropTrailingSlash(PreferencesData.CertDir);
    }

    if ( PreferencesData.LogDir[0] == 0 )
    {
        strcpy_s(PreferencesData.LogDir, MAX_PATH, ".\\");
    }
    else
    {
        cropTrailingSlash(PreferencesData.LogDir);
    }

    if ( PreferencesData.FileDir[0] == 0 )
    {
        strcpy_s(PreferencesData.FileDir, MAX_PATH, ".\\");
    }
    else
    {
        cropTrailingSlash(PreferencesData.FileDir);
    }
}

//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXA wcex;

    wcex.cbSize = sizeof(WNDCLASSEXA);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = gui_icon_off;
    wcex.hCursor = LoadCursorA(nullptr, IDC_ARROW);
    wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wcex.lpszMenuName = MAKEINTRESOURCEA(IDC_GUI);
    wcex.lpszClassName = WindowClass;
    wcex.hIconSm = gui_icon_off;
    //wcex.hIconSm = small_icon_off;

    return RegisterClassExA(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    MainInstance = hInstance; // Store instance handle in our global variable
    
    HWND Desktop = GetDesktopWindow();
    RECT DesktopRect;
    GetClientRect(Desktop, &DesktopRect);

    INT x = (DesktopRect.right - DEFAULT_WINDOW_WIDTH) / 2;
    INT y = (DesktopRect.bottom - DEFAULT_WINDOW_HEIGHT) / 2;
    if ( x < 0 )
        x = 0;
    if ( y < 0 )
        y = 0;

    MainRect = { x, y, DEFAULT_WINDOW_WIDTH, DEFAULT_WINDOW_HEIGHT };

    MainWindow = CreateWindowExA(
        0,
        WindowClass,
        WindowTitle,
        WS_OVERLAPPEDWINDOW | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        x,
        y,
        DEFAULT_WINDOW_WIDTH,
        DEFAULT_WINDOW_HEIGHT,
        NULL,
        NULL,
        hInstance,
        nullptr
    );


    if ( !MainWindow )
    {
        return FALSE;
    }

    ShowWindow(MainWindow, nCmdShow);
    UpdateWindow(MainWindow);

    return TRUE;
}

BOOL CALLBACK EnumChildProc(HWND hwndChild, LPARAM lParam)
{
    int idChild;
    idChild = GetWindowLong(hwndChild, GWL_ID);
    LPRECT rcParent = (LPRECT)lParam;
    LPRECT rcChild = NULL;
    
    INT ParentW = rcParent->right;
    INT ParentH = rcParent->bottom;
    
    INT newX, newY, newW, newH; 

    // check min width
    if ( rcParent->right < MIN_WINDOW_WIDTH && rcParent->bottom < MIN_WINDOW_HEIGHT )
        return TRUE;

    if ( rcParent->right < MIN_WINDOW_WIDTH )
        ParentW = MIN_WINDOW_WIDTH;
    if ( rcParent->bottom < MIN_WINDOW_HEIGHT )
        ParentH = MIN_WINDOW_HEIGHT;

    // check child id
    if ( idChild == WND_MESSAGE_OPT_IDX )
        rcChild = &MessageOptRect;
    else if ( idChild == WND_STATUS_OPT_IDX )
        rcChild = &StatusOptRect;
    else if ( idChild == WND_INFO_STATUS_OPT_IDX )
        rcChild = &InfoStatusOptRect;
    else if ( idChild == WND_MESSAGE_IPT_IDX || WND_FILE_BTN_IDX || WND_SEND_BTN_IDX || WND_FILE_PROGRESS_IDX )
        rcChild = &MessageIptRect;
    else
        return TRUE;

//#ifdef DEBUG_PRINT
//    std::string s = "left: "+std::to_string(rcParent->left)
//        +", top: "+std::to_string(rcParent->top)
//        +", right: "+std::to_string(rcParent->right)
//        +", bottom: "+std::to_string(rcParent->bottom);
//    showStatus(s.c_str());
//#endif

    if ( idChild == WND_MESSAGE_OPT_IDX )
    {
        newX = (INT)(rcChild->left);
        newY = (INT)(rcChild->top);
        newW = (INT)(ParentW - PARENT_PADDING*2);
        newH = (INT)(ParentH - rcChild->top - PARENT_PADDING*3);
    }
    else if ( idChild == WND_MESSAGE_IPT_IDX )
    {
        newX = (INT)(rcChild->left);
        newY = (INT)(rcChild->top);
        newW = (INT)(ParentW - rcChild->left - BTN_W*2 - PARENT_PADDING - IPT_MARGIN*2);
        newH = (INT)(rcChild->bottom);
    }
    else if ( idChild == WND_FILE_BTN_IDX )
    {
        newX = (INT)(ParentW - BTN_W - PARENT_PADDING);
        newY = (INT)(rcChild->top);
        newW = (INT)(BTN_W);
        newH = (INT)(BTN_H);
    }
    else if ( idChild == WND_SEND_BTN_IDX )
    {
        newX = (INT)(ParentW - BTN_W*2 - PARENT_PADDING - IPT_MARGIN);
        newY = (INT)(rcChild->top);
        newW = (INT)(BTN_W);
        newH = (INT)(BTN_H);
    }
    else if ( idChild == WND_FILE_PROGRESS_IDX )
    {
        newX = (INT)(ParentW - DEFAULT_PROG_BAR_W - PARENT_PADDING);
        newY = (INT)(rcChild->top - DEFAULT_PROG_BAR_H);
        newW = (INT)(DEFAULT_PROG_BAR_W);
        newH = (INT)(DEFAULT_PROG_BAR_H);
    }
    else if ( idChild == WND_STATUS_OPT_IDX )
    {
        newX = (INT)(rcChild->left);
        newY = (INT)(ParentH - IPT_H);
        newW = (INT)(rcChild->right);
        newH = (INT)(rcChild->bottom);
    }
    else if ( idChild == WND_INFO_STATUS_OPT_IDX )
    {
        newX = (INT)(rcChild->left);
        newY = (INT)(ParentH - IPT_H);
        newW = (INT)(ParentW - STATUS_OPT_W+STATUS_MARGIN);
        newH = (INT)(rcChild->bottom);
    }
    else
        return TRUE;


    MoveWindow(hwndChild, newX, newY, newW, newH, TRUE);

    // Make sure the child window is visible. 
    //ShowWindow(hwndChild, SW_SHOW);

    return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE: Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    LRESULT result = 0;
    std::string r;

    switch ( message )
    {
    case WM_COMMAND:
        result = onCommand(hWnd, message, wParam, lParam);
        break;

    case WM_CREATE:
        result = onCreate(hWnd);
        break;

    case WM_PAINT:
        result = onPaint(hWnd);
        break;
    
    case WM_SIZE:
        GetClientRect(hWnd, &MainRect);
        EnumChildWindows(hWnd, EnumChildProc, (LPARAM)&MainRect);
        return 0;

    case WM_CLOSE:
        result = ConfirmClose(hWnd);
        if ( result == IDOK )
            return DefWindowProcA(hWnd, message, wParam, lParam);
        else
            break;

    case WM_DESTROY:
        result = onDestroy(hWnd);
        break;

    default:
        return DefWindowProcA(hWnd, message, wParam, lParam);
    }
    return result;
}

LRESULT onCommand(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam)
{
    LRESULT result = 0;
    int wmId = LOWORD(wParam);
    std::string r;

    switch ( wmId )
    {
    case WND_CONNECT_BTN_IDX:
        result = onConnect(hWnd);
        break;

    case WND_LISTEN_BTN_IDX:
        result = onListen(hWnd);
        break;

    case WND_FILE_BTN_IDX:
        result = onSelectFile(hWnd, FOS_FORCEFILESYSTEM, MessageIpt, MSG_CMD_FILE);
        break;

    case WND_SEND_BTN_IDX:
        result = onSend(hWnd);
        break;

    case IDM_ABOUT:
        DialogBoxParamA(MainInstance, MAKEINTRESOURCEA(IDD_ABOUT_DLG), hWnd, AboutDialogCB, 0L);
        break;

    case IDM_PREFS:
        result = (LRESULT)DialogBoxParamA(MainInstance, MAKEINTRESOURCEA(IDD_PREFS_DLG), hWnd, PrefsDialogCB, 0L);
        if ( PreferencesDlg.hasChanged() )
        {
            DataHasChanged = true;
            SetWindowTextA(MainWindow, WindowTitleC);
        }
        break;

    case IDM_CONN_DATA:
        DialogBoxParamA(MainInstance, MAKEINTRESOURCEA(IDD_CONN_DATA_DLG), hWnd, ConnectionDataDialogCB, 0L);
        if ( ConnectionDataDlg.hasChanged() )
        {
            DataHasChanged = true;
            SetWindowTextA(MainWindow, WindowTitleC);
        }
        break;

    //case WM_CTLCOLORSTATIC:
    //    SetWindowTextA(CertFileIpt, "WM_CTLCOLORSTATIC");
    //    break;

    case IDM_SAVE:
        onSafeData();
        break;

    case IDM_EXIT:
        result = ConfirmClose(hWnd);
        if ( result == IDOK )
            DestroyWindow(hWnd);
        break;

    default:
        return DefWindowProcA(hWnd, message, wParam, lParam);
    }

    return result;
}

LRESULT onSafeData()
{
    LRESULT result = 0;

    updateConfigFile(&ConnectionData, &PreferencesData);
    result = CfgFileParser->save(CfgFile.Path);
    
    if ( result != 0 )
        showInfoStatus("Saving failed");
    else
    {
        showInfoStatus("Saved");
        SetWindowText(MainWindow, WindowTitleD);
        DataHasChanged = FALSE;
    }

    return result;
}

// Message handler for about box.
INT_PTR CALLBACK AboutDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    (lParam);

    ABOUT_DIALOG_PARAMS params;
    params.BinaryName = REL_NAME;
    params.ActVersion = REL_VS;
    params.LastChanged = REL_DATE;
    params.CompileDate = COMPILE_DATE;
    params.CompileTime = COMPILE_TIME;

    return AboutDlg.openCb(hDlg, message, wParam, (LPARAM)&params);
}

 //Message handler for prefs box.
INT_PTR CALLBACK PrefsDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    (lParam);
    return PreferencesDlg.openCb(hDlg, message, wParam, (LPARAM)&PreferencesData);
}

 //Message handler for connection data
INT_PTR CALLBACK ConnectionDataDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    (lParam);
    return ConnectionDataDlg.openCb(hDlg, message, wParam, (LPARAM)&ConnectionData);
}

INT ConfirmClose(HWND hWnd)
{
    INT result = IDOK;
    
    if ( ConnectionStatus == CONNECTION_STATUS::CONNECTED )
    {
        COMFIRM_CLOSE_PARAMS p = {
            "You are still connected.",
            "Close connection and exit?"
        };
        result = (INT)DialogBoxParamA(MainInstance, MAKEINTRESOURCEA(IDD_CLOSE_DLG), hWnd, onCloseCB, (LPARAM)&p);
    }
    
    if ( result == IDOK && DataHasChanged )
    {
        COMFIRM_CLOSE_PARAMS p = {
            "Your settings have unsaved changes.",
            "Exit anyway?"
        };
        result = (INT)DialogBoxParamA(MainInstance, MAKEINTRESOURCEA(IDD_CLOSE_DLG), hWnd, onCloseCB, (LPARAM)&p);
    }

    return result;
}

INT_PTR CALLBACK onCloseCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    return CloseDlg.openCb(hDlg, message, wParam, lParam);
}

LRESULT onDestroy(HWND hWnd)
{
    LRESULT result = 0;
    UNREFERENCED_PARAMETER(hWnd);

    if ( ConnectionThread != NULL )
        CloseHandle(ConnectionThread);
    stopNetworking();

    DestroyIcon(gui_icon_off);
    DestroyIcon(gui_icon_on);
    DestroyIcon(gui_icon_listen);
    FreeResource(notify_snd);
    
    KillTimer(MainWindow, IDT_INFO_TIMER); 

    if ( pmsg )
        delete[] pmsg;

    if ( CfgFileParser )
        delete CfgFileParser;

    PostQuitMessage(0);
    return result;
}

INT_PTR CALLBACK FTAcceptDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    return FileTransferDlg.openCb(hDlg, message, wParam, lParam);
}

LRESULT CALLBACK MesageIptSC(HWND hWnd, UINT msg, WPARAM wParam,
                               LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
    LRESULT result = 0;
    (uIdSubclass);(dwRefData);

    switch (msg)
    {
        case WM_CHAR :
            switch ( wParam ) {
                case VK_RETURN :
                    onSend(hWnd);
                    return 0;
            }

       default:
           result = DefSubclassProc(hWnd, msg, wParam, lParam);
    } 
    return result;
}

//#include "Richedit.h"
//#include "commctrl.h"


LRESULT onCreate(HWND hWnd)
{
    LRESULT result = 0;

    int file_btn_x = DEFAULT_WINDOW_WIDTH - PARENT_PADDING;
    int msg_box_w = 600;
    int msg_box_h = 230;

    MessageIptRect.left = PARENT_PADDING;
    MessageIptRect.top = rows_y[3];
    MessageIptRect.right = DEFAULT_WINDOW_WIDTH - PARENT_PADDING*2 - BTN_W*2 - IPT_MARGIN*2;
    MessageIptRect.bottom = IPT_H;
    MessageIpt = CreateWindowExA(
        0, // WS_EX_CLIENTEDGE
        WC_EDITA, 
        (pmsg)?pmsg:"", 
        WS_BORDER | WS_CHILD | WS_VISIBLE  | ES_AUTOHSCROLL | ES_MULTILINE,
        MessageIptRect.left, MessageIptRect.top, MessageIptRect.right, MessageIptRect.bottom,
        hWnd, 
        (HMENU)WND_MESSAGE_IPT_IDX, 
        GetModuleHandle(NULL), 
        NULL
    );
    SetWindowSubclass(MessageIpt, MesageIptSC, WND_MESSAGE_IPT_IDX, 0);

    SendBtn = CreateWindowA(
        WC_BUTTONA,
        "Send",
        WS_CHILD | WS_VISIBLE | WS_GROUP | WS_TABSTOP,
        MessageIptRect.left + MessageIptRect.right + IPT_MARGIN, rows_y[3], BTN_W, BTN_H,
        hWnd, (HMENU)WND_SEND_BTN_IDX, NULL, NULL
    );
    ToolTip::forChild(SendBtn, hWnd, "Send message.");

    SelFileBtn = CreateWindowA(
        WC_BUTTONA,
        FILE_BTN_SELECT_STR,
        WS_CHILD | WS_VISIBLE | WS_GROUP | WS_TABSTOP,
        file_btn_x, rows_y[3], BTN_W, BTN_H,
        hWnd, (HMENU)WND_FILE_BTN_IDX, NULL, NULL
    );
    ToolTip::forChild(SelFileBtn, hWnd, "Select a file to send.");
     
    //LoadLibrary("Msftedit.dll");
    //    MessageOpt = CreateWindowExA(0, "RICHEDIT50W", "Type here",
    //    WS_BORDER | WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 
    //    ipt_x, rows_y[6], msg_box_w, msg_box_h,
    //    hWnd, (HMENU)WND_MESSAGE_OPT_IDX, MainInstance, NULL);
    MessageOptRect.left = PARENT_PADDING;
    MessageOptRect.top = rows_y[4];
    MessageOptRect.right = msg_box_w;
    MessageOptRect.bottom = msg_box_h;
    MessageOpt = CreateWindowA(
        WC_EDITA,
        "",
        WS_BORDER | WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
        MessageOptRect.left, MessageOptRect.top, MessageOptRect.right, MessageOptRect.bottom,
        hWnd, (HMENU)WND_MESSAGE_OPT_IDX, NULL, NULL
    );

    ListenBtn = CreateWindowExA(
        0,
        WC_BUTTONA,
        "Listen",
        WS_CHILD | WS_VISIBLE | WS_GROUP | WS_TABSTOP,
        PARENT_PADDING, rows_y[0], BTN_W, BTN_H,
        hWnd, (HMENU)WND_LISTEN_BTN_IDX, NULL, NULL
    );
    //ToolTip::forChild(ListenBtn, hWnd, "Start listening.");

    ConnectBtn = CreateWindowExA(
        0,
        WC_BUTTONA,
        "Connect",
        WS_CHILD | WS_VISIBLE | WS_GROUP | WS_TABSTOP,
        PARENT_PADDING + IPT_MARGIN + BTN_W, rows_y[0], BTN_W, BTN_H,
        hWnd, (HMENU)WND_CONNECT_BTN_IDX, NULL, NULL
    );
    //ToolTip::forChild(ConnectBtn, hWnd, "Connect to a listening server.");

    FilePBar = CreateWindowExA(
                0, 
                PROGRESS_CLASS, 
                (LPTSTR) NULL, 
                WS_CHILD | WS_VISIBLE, 
                file_btn_x, rows_y[4], DEFAULT_PROG_BAR_W, DEFAULT_PROG_BAR_H,
                hWnd, 
                (HMENU)WND_FILE_PROGRESS_IDX, 
                GetModuleHandle(NULL), 
                NULL
            );
    SendMessage(FilePBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    ShowWindow(FilePBar, SW_HIDE);



    StatusOptRect.left = 0;
    StatusOptRect.top = DEFAULT_WINDOW_HEIGHT - 20;
    StatusOptRect.right = STATUS_OPT_W;
    StatusOptRect.bottom = IPT_H;
    ConnStatusOpt = CreateWindowA(
        WC_EDITA,
        "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        StatusOptRect.left, StatusOptRect.top, StatusOptRect.right, StatusOptRect.bottom,
        hWnd, (HMENU)WND_STATUS_OPT_IDX, NULL, NULL
    );



    InfoStatusOptRect.left = STATUS_OPT_W + STATUS_MARGIN;
    InfoStatusOptRect.top = DEFAULT_WINDOW_HEIGHT - 20;
    InfoStatusOptRect.right = DEFAULT_WINDOW_WIDTH - STATUS_OPT_W + STATUS_MARGIN;
    InfoStatusOptRect.bottom = IPT_H;
    InfoStatusOpt = CreateWindowA(
        WC_EDITA,
        "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        InfoStatusOptRect.left, InfoStatusOptRect.top, InfoStatusOptRect.right, InfoStatusOptRect.bottom,
        hWnd, (HMENU)WND_INFO_STATUS_OPT_IDX, NULL, NULL
    );


    
    setConnStatusOutput(ConnStatusOpt);
    setInfoStatusOutput(InfoStatusOpt);
    setMessageOutput(MessageOpt);
    setFilePBar(FilePBar);

    sayHello();
    if ( type == 1 )
        onListen(MainWindow);
    else if ( type == 2 )
        onConnect(MainWindow);

    return result;
}

LRESULT onPaint(HWND hWnd)
{
    LRESULT result = 0;
    CHAR message_lbl[] = "Message";

    int lbl_x = 10;
    //int lbl_x2 = 425;

    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hWnd, &ps);

    TextOutA(hdc, lbl_x, rows_y[2], message_lbl, (int)strlen(message_lbl));

    EndPaint(hWnd, &ps);
    
    return result;
}

__forceinline
ADDRESS_FAMILY deriveFamily(PCHAR ip_, size_t n)
{
    if ( n >= MAX_IP_LN )
        return 0;
    
    if ( n == 0 )
    {
        return ConnectionData.family;
    }

    char* ptr = strstr(ip_, ".");
    if ( ptr != NULL )
        return AF_INET;
    ptr = strstr(ip_, ":");
    if ( ptr != NULL )
        return AF_INET6;
    
    else if ( n == 1 )
        ip_[0] = 0;

    return 0;
}

VOID changeIcon(CONNECTION_STATUS status)
{
    if ( status == CONNECTION_STATUS::CONNECTED )
    {
        SendMessage(MainWindow, WM_SETICON, ICON_SMALL, (LPARAM)(gui_icon_on));
        SendMessage(MainWindow, WM_SETICON, ICON_BIG, (LPARAM)(gui_icon_on));
    }
    else if ( status == CONNECTION_STATUS::LISTENING )
    {
        SendMessage(MainWindow, WM_SETICON, ICON_SMALL, (LPARAM)(gui_icon_listen));
        SendMessage(MainWindow, WM_SETICON, ICON_BIG, (LPARAM)(gui_icon_listen));
    }
    else
    {
        SendMessage(MainWindow, WM_SETICON, ICON_SMALL, (LPARAM)(gui_icon_off));
        SendMessage(MainWindow, WM_SETICON, ICON_BIG, (LPARAM)(gui_icon_off));
    }
}

VOID setupNetClient()
{
    ConnectionData.family = deriveFamily(ConnectionData.ip, strlen(ConnectionData.ip));
    family = ConnectionData.family;
        
    client_setLogDir(PreferencesData.LogDir);
    client_setCertDir(PreferencesData.CertDir);
    client_setFileDir(PreferencesData.FileDir);

    client_setNick(ConnectionData.name);
}

void enableConnectedControls(HWND btn)
{
    ConnectionDataDlg.enable();
    PreferencesDlg.enable();
    EnableWindow(btn, TRUE);
}

void disableConnectedControls(HWND btn)
{
    ConnectionDataDlg.disable();
    PreferencesDlg.disable();
    EnableWindow(btn, FALSE);
}

LRESULT onConnect(HWND hWnd)
{
    LRESULT result = 0;
    UNREFERENCED_PARAMETER(hWnd);
    
    initLog("client");

    if ( ConnectionStatus == CONNECTION_STATUS::STOPPING )
        return 0;

    if ( ConnectionStatus == CONNECTION_STATUS::LISTENING )
    {
        showInfoStatus("Already in listening mode, can't connect at the same time!");

        return 0;
    }

    if ( ConnectionStatus == CONNECTION_STATUS::STOPPED )
    {
        if ( ConnectionThread != NULL )
        {
            showInfoStatus("ERROR: Connectino thread not NULL");
            return -1;
        }
        ConnectionThread = NULL;
        ConnectionThreadId = 0;

        setupNetClient();

        result = initClient(ConnectionData.ip, ConnectionData.port, ConnectionData.family, ConnectionData.CertThumb);
        if ( result != 0 )
        {
            sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Connecting failed: 0x%X", (INT)result);
            showInfoStatus(err_msg);
            goto clean;
        }

        ConnectionThread = CreateThread(
            NULL,                   // default security attributes
            0,                      // use default stack size  
            ReceiveThreadFn,       // thread function name
            hWnd,        // argument to thread function 
            0,           // use default creation flags 
            &ConnectionThreadId    // returns the thread identifier 
        );
        if ( ConnectionThread == NULL )
        {
            showInfoStatus("Creating receive thread failed!");
            stopConnection(hWnd, "Disconnected", ConnectBtn, "Connect", ListenBtn);
            goto clean;
        }
        CloseHandle(ConnectionThread);
        ConnectionThread = NULL;
        
        disableConnectedControls(ListenBtn);
        showConnStatus("Connected");
        changeIcon(CONNECTION_STATUS::CONNECTED);
        SetWindowTextA(ConnectBtn, "Stop");

        cstmtx.lock();
        ConnectionStatus = CONNECTION_STATUS::CONNECTED;
        cstmtx.unlock();
    }
    else if ( ConnectionStatus == CONNECTION_STATUS::CONNECTED )
    {
        stopConnection(hWnd, "Disconnected", ConnectBtn, "Connect", ListenBtn);
    }

clean:
    ;

    return result;
}

LRESULT onListen(HWND hWnd)
{
    LRESULT result = 0;
    UNREFERENCED_PARAMETER(hWnd);
    CHAR buffer[0x50];

    initLog("server");

    if ( ConnectionStatus == CONNECTION_STATUS::STOPPING )
        return 0;

    if ( ConnectionStatus == CONNECTION_STATUS::CONNECTED )
    {
        showInfoStatus("Already in connected mode, can't listen at the same time!");

        return 0;
    }

    if ( ConnectionStatus == CONNECTION_STATUS::STOPPED )
    {
        if ( ConnectionThread != NULL )
        {
            showInfoStatus("ERROR: ConnectionThread not NULL");
            return -1;
        }
        ConnectionThread = NULL;
        ConnectionThreadId = 0;

        setupNetClient();

        result = initServer(ConnectionData.ip, ConnectionData.port, ConnectionData.family, ConnectionData.CertThumb);
        if ( result != 0 )
        {
            sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Listening failed: 0x%X", (INT)result);
            showInfoStatus(err_msg);
            goto clean;
        }

        ConnectionThread = CreateThread(
            NULL,         // default security attributes
            0,            // use default stack size  
            ListenThread, // thread function name
            hWnd,        // argument to thread function 
            0,           // use default creation flags 
            &ConnectionThreadId    // returns the thread identifier 
        );
        if ( ConnectionThread == NULL )
        {
            showInfoStatus("Creating listen thread failed!");
            stopConnection(hWnd, "Deaf", ListenBtn, "Listen", ConnectBtn);
            goto clean;
        }
        CloseHandle(ConnectionThread);
        ConnectionThread = NULL;
        
        disableConnectedControls(ConnectBtn);
        SetWindowTextA(ListenBtn, "Stop");
        sprintf_s(buffer, 0x50, "Listening on %s", ConnectionData.port);
        showConnStatus(buffer);
        changeIcon(CONNECTION_STATUS::LISTENING);
        
        cstmtx.lock();
        ConnectionStatus = CONNECTION_STATUS::LISTENING;
        cstmtx.unlock();
    }
    else if ( ConnectionStatus == CONNECTION_STATUS::LISTENING )
    {
        stopConnection(hWnd, "Deaf", ListenBtn, "Listen", ConnectBtn);
    }

clean:
    ;

    return result;
}

LRESULT onSend(HWND hWnd)
{
    LRESULT r = 0;
    UNREFERENCED_PARAMETER(hWnd);
    
    int msg_len = GetWindowTextLengthA(MessageIpt) + 1;
    if ( msg_len < 2 )
    {
        showInfoStatus("Type a message first!");
        return 0;
    }

    char* msg = new char[msg_len];
    GetWindowTextA(MessageIpt, &msg[0], msg_len);

    if ( startsWith(MSG_CMD_FILE,  msg) )
        r = sendFile(msg, msg_len);
    else
        r = sendMessage(msg, msg_len);

    //if ( r != 0 )
    //    return r;
    
    if ( msg )
        delete[] msg;

    return r;
}

LRESULT sendMessage(PCHAR msg, ULONG msg_len)
{
    LRESULT r = 0;

    showInfoStatus("Sending...");

    r = client_sendMessage(msg, msg_len);
    if ( (ULONG)r == SCHAT_ERROR_INVALID_SOCKET )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Not connected yet!");
        showInfoStatus(err_msg);
    }
    else if ( (ULONG)r != 0 )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Send error: 0x%X", (ULONG)r);
        showInfoStatus(err_msg);
    }
    else
    {
        SetWindowTextA(MessageIpt, "");
        showInfoStatus("");
    }

    return r;
}

LRESULT sendFile(PCHAR msg, ULONG msg_len)
{
    LRESULT r = 0;

    showInfoStatus("Sending...");

    if ( msg_len <= MSG_CMD_FILE_LN+1 )
    {
        showInfoStatus("Path too short!");
        return -1;
    }

    PCHAR path = &msg[MSG_CMD_FILE_LN];
    ULONG path_len = (ULONG)strlen(path);
    
    if ( path_len < 2 )
    {
        showInfoStatus("Path too short!");
        return -1;
    }

    r = client_sendFile(path, path_len, ConnectionData.ip, ConnectionData.port, ConnectionData.family);
    if ( (ULONG)r == SCHAT_ERROR_INVALID_SOCKET )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Not connected yet!");
        showInfoStatus(err_msg);
    }
    else if ( (ULONG)r != 0 )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Send file error : 0x%X", (ULONG)r);
        showInfoStatus(err_msg);
    }
    else
    {
        SetWindowTextA(MessageIpt, "");
        //showStatus("");
    }

    return r;
}

VOID toggleFileBtn(FILE_TRANSFER_STATUS state)
{
    if ( FileTransferStatus == state )
        return;

    FileTransferStatus = state;

    if ( state == FILE_TRANSFER_STATUS::ACTIVE )
    {
        SetWindowTextA(SelFileBtn, FILE_BTN_CANCEL_STR);

    }
    else if ( state == FILE_TRANSFER_STATUS::STOPPED )
    {
        SetWindowTextA(SelFileBtn, FILE_BTN_SELECT_STR);
    }
}

LRESULT CancelFileTransfer()
{
    //toggleFileBtn(FILE_TRANSFER_STATUS::STOPPED);
    client_cancelFileTransfer();

    return 0;
}

/**
 * Start client receiving thread
 */
DWORD WINAPI ReceiveThreadFn(LPVOID lpParam)
{
    int s = 0;
    HWND hWnd = (HWND)(lpParam);
    
    char msg[0x1000];
    uint32_t len = 0x1000;

    s = receiveMessages(
        msg, 
        len,
        NULL,
        0
    );
    
    stopConnection(hWnd, "Disconnected", ConnectBtn, "Connect", ListenBtn);

    return s;
}

DWORD WINAPI ListenThread(LPVOID lpParam)
{
    int s = 0;
    HWND hWnd = (HWND)(lpParam);
    
    char msg[0x1];
    uint32_t len = 0x1;

    s = client_handleConnections(
        msg, 
        len
    );
    
    stopConnection(hWnd, "Deaf", ListenBtn, "Listen", ConnectBtn);

    return s;
}

VOID stopConnection(HWND hWnd, const char* msg, HWND btn, const char* btnText, HWND otherBtn)
{
    UNREFERENCED_PARAMETER(hWnd);
    
    if ( ConnectionStatus == CONNECTION_STATUS::STOPPED || 
         ConnectionStatus == CONNECTION_STATUS::STOPPING )
        return;

    cstmtx.lock();
    ConnectionStatus = CONNECTION_STATUS::STOPPING;
    cstmtx.unlock();

    cleanClient();
    showConnStatus(msg);
    SetWindowTextA(btn, btnText);

    enableConnectedControls(otherBtn);
    //SendMessageA(NameIpt, EM_SETREADONLY, FALSE, NULL);
    //EnableWindow(otherBtn, TRUE);

    ConnectionThread = NULL;
    ConnectionThreadId = 0;

    changeIcon(CONNECTION_STATUS::STOPPED);
    
    cstmtx.lock();
    ConnectionStatus = CONNECTION_STATUS::STOPPED;
    cstmtx.unlock();
}

VOID stopNetworking()
{
    if ( ConnectionStatus == CONNECTION_STATUS::STOPPED || 
         ConnectionStatus == CONNECTION_STATUS::STOPPING )
        return;

    cstmtx.lock();
    ConnectionStatus = CONNECTION_STATUS::STOPPING;
    cstmtx.unlock();

    showConnStatus("Stopping...");
    cleanClient();
    showConnStatus("Stopped");
    
    cstmtx.lock();
    ConnectionStatus = CONNECTION_STATUS::STOPPED;
    cstmtx.unlock();
}

LRESULT onSelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix)
{
    if ( FileTransferStatus == FILE_TRANSFER_STATUS::STOPPED )
    {
        return FileSel.select(hWnd, flags, output, prefix);
    }
    else if ( FileTransferStatus == FILE_TRANSFER_STATUS::ACTIVE )
    {
        return CancelFileTransfer();
    }
    return 0;
}

#define GUI_HELLO_MSG_LN (0x200)
VOID sayHello()
{
    
    SYSTEMTIME sts;
    GetLocalTime(&sts);

    char hello[GUI_HELLO_MSG_LN];
    int o = 0;
    o += sprintf_s(hello, GUI_HELLO_MSG_LN, "%s\r\n", REL_NAME);
    o += sprintf_s(&hello[o], GUI_HELLO_MSG_LN - o, "Version: %s - %s\r\n", REL_VS, REL_DATE);
    o += sprintf_s(&hello[o], GUI_HELLO_MSG_LN - o, "Compiled: %s -- %s\r\n\r\n", COMPILE_DATE, COMPILE_TIME);

    SetWindowTextA(MessageOpt, hello);
}
#undef GUI_HELLO_MSG_LN

BOOL loadSound(
    LPSTR lpName, 
    HGLOBAL* Res
) 
{ 
    HRSRC hResInfo;
 
    // Find the WAVE resource. 
    hResInfo = FindResourceA(MainInstance, lpName, "WAVE"); 
    if (hResInfo == NULL) 
        return FALSE; 
 
    // Load the WAVE resource. 
    *Res = LoadResource((HMODULE)MainInstance, (HRSRC)hResInfo); 
    if ( *Res == NULL )
        return FALSE; 
 
    return TRUE; 
} 

void parseConfigFile()
{
    const CHAR* config_name = ".config";
    //size_t conifg_name_ln = strlen(config_name);
    ULONG path_ln = GetFullPathNameA(config_name, MAX_PATH, CfgFile.Path, NULL);
    if ( path_ln == 0 || path_ln == MAX_PATH )
    {
        CfgFile.Path[0] = 0;
        return;
    }
    CfgFile.Path[path_ln] = 0;

    bool s = CfgFileParser->run(CfgFile.Path);
    if ( !s )
        return;


    std::string tempStr;
    std::uint16_t tempShrt;


    // 
    // Connnection Data
    //
    
    if ( ConnectionData.ip[0] == 0 )
    {
        tempStr = CfgFileParser->getStringValue(CfgFile.Keys[0], MAX_IP_LN-1, "");
        strcpy_s(ConnectionData.ip, MAX_IP_LN, &tempStr[0]);
    }

    if ( ConnectionData.port[0] == 0 )
    {
        tempStr = CfgFileParser->getStringValue(CfgFile.Keys[1], MAX_PORT_LN-1, "");
        strcpy_s(ConnectionData.port, MAX_PORT_LN, &tempStr[0]);
    }

    if ( ConnectionData.family == AF_UNSPEC )
    {
        tempShrt = CfgFileParser->getUInt16Value(CfgFile.Keys[2], AF_UNSPEC);
        
        if ( tempShrt == 4 )
        {
            family = AF_INET;
            ConnectionData.family = AF_INET;
        }
        else if ( tempShrt == 6 )
        {
            family = AF_INET6;
            ConnectionData.family = AF_INET6;
        }
    }

    if ( ConnectionData.name[0] == 0 )
    {
        tempStr = CfgFileParser->getStringValue(CfgFile.Keys[3], MAX_NAME_LN-1, "");
        strcpy_s(ConnectionData.name, MAX_NAME_LN, &tempStr[0]);
    }

    if ( ConnectionData.CertThumb[0] == 0 )
    {
        tempStr = CfgFileParser->getStringValue(CfgFile.Keys[4], SHA1_STRING_BUFFER_LN-1, "");
        strcpy_s(ConnectionData.CertThumb, SHA1_STRING_BUFFER_LN, &tempStr[0]);
    }


    // 
    // Preferences
    //

    if ( PreferencesData.LogDir[0] == 0 )
    {
        tempStr = CfgFileParser->getStringValue(CfgFile.Keys[5], MAX_PATH-1, "");
        strcpy_s(PreferencesData.LogDir, MAX_PATH, &tempStr[0]);
        cropTrailingSlash(PreferencesData.LogDir);
        GetFullPathName(PreferencesData.LogDir, MAX_PATH, PreferencesData.LogDir, NULL);
    }

    if ( PreferencesData.CertDir[0] == 0 )
    {
        tempStr = CfgFileParser->getStringValue(CfgFile.Keys[6], MAX_PATH-1, "");
        strcpy_s(PreferencesData.CertDir, MAX_PATH, &tempStr[0]);
        cropTrailingSlash(PreferencesData.CertDir);
        GetFullPathName(PreferencesData.CertDir, MAX_PATH, PreferencesData.CertDir, NULL);
    }

    if ( PreferencesData.FileDir[0] == 0 )
    {
        tempStr = CfgFileParser->getStringValue(CfgFile.Keys[7], MAX_PATH-1, "");
        strcpy_s(PreferencesData.FileDir, MAX_PATH, &tempStr[0]);
        cropTrailingSlash(PreferencesData.FileDir);
        GetFullPathName(PreferencesData.FileDir, MAX_PATH, PreferencesData.FileDir, NULL);
    }
}

VOID updateConfigFile(PCONNECTION_DATA ConnData, PPREFERENCES_DATA PrefsData)
{
    std::string tmpStr;
    uint16_t tmpShrt;

    tmpStr = CfgFileParser->getStringValue(CfgFile.Keys[CONFIG_FILE_KEY_IP], MAX_IP_LN-1, "");
    if ( strcmp(&tmpStr[0], ConnData->ip) != 0 )
    {
        CfgFileParser->setStringValue(CfgFile.Keys[CONFIG_FILE_KEY_IP], ConnData->ip, strlen(ConnData->ip));
    }

    tmpStr = CfgFileParser->getStringValue(CfgFile.Keys[CONFIG_FILE_KEY_PORT], MAX_PORT_LN-1, "");
    if ( strcmp(&tmpStr[0], ConnData->port) != 0 )
    {
        CfgFileParser->setStringValue(CfgFile.Keys[CONFIG_FILE_KEY_PORT], ConnData->port, strlen(ConnData->port));
    }

    tmpShrt = CfgFileParser->getUInt16Value(CfgFile.Keys[CONFIG_FILE_KEY_IP_VS], AF_UNSPEC);
    if ( tmpShrt == 4 )
        tmpShrt = AF_INET;
    else if ( tmpShrt == 6 )
        tmpShrt = AF_INET6;
    if ( tmpShrt != ConnData->family )
    {
        if ( tmpShrt == AF_INET )
            tmpShrt = 4;
        else if ( tmpShrt == AF_INET6 )
            tmpShrt = 6;
        else
            tmpShrt = 0;

        CfgFileParser->setUInt16Value(CfgFile.Keys[CONFIG_FILE_KEY_IP_VS], tmpShrt);
    }

    tmpStr = CfgFileParser->getStringValue(CfgFile.Keys[CONFIG_FILE_KEY_USER_NAME], MAX_NAME_LN-1, "");
    if ( strcmp(&tmpStr[0], ConnData->name) != 0 )
    {
        CfgFileParser->setStringValue(CfgFile.Keys[CONFIG_FILE_KEY_USER_NAME], ConnData->name, strlen(ConnData->name));
    }

    tmpStr = CfgFileParser->getStringValue(CfgFile.Keys[CONFIG_FILE_KEY_CERT_THUMB], SHA1_STRING_BUFFER_LN-1, "");
    if ( strcmp(&tmpStr[0], ConnData->CertThumb) != 0 )
    {
        CfgFileParser->setStringValue(CfgFile.Keys[CONFIG_FILE_KEY_CERT_THUMB], ConnData->CertThumb, strlen(ConnData->CertThumb));
    }

    tmpStr = CfgFileParser->getStringValue(CfgFile.Keys[CONFIG_FILE_KEY_LOG_FILES], MAX_PATH-1, "");
    if ( strcmp(&tmpStr[0], PrefsData->LogDir) != 0 )
    {
        CfgFileParser->setStringValue(CfgFile.Keys[CONFIG_FILE_KEY_LOG_FILES], PrefsData->LogDir, strlen(PrefsData->LogDir));
    }

    tmpStr = CfgFileParser->getStringValue(CfgFile.Keys[CONFIG_FILE_KEY_CERT_FILES], MAX_PATH-1, "");
    if ( strcmp(&tmpStr[0], PrefsData->CertDir) != 0 )
    {
        CfgFileParser->setStringValue(CfgFile.Keys[CONFIG_FILE_KEY_CERT_FILES], PrefsData->CertDir, strlen(PrefsData->CertDir));
    }

    tmpStr = CfgFileParser->getStringValue(CfgFile.Keys[CONFIG_FILE_KEY_T_FILES], MAX_PATH-1, "");
    if ( strcmp(&tmpStr[0],  PrefsData->FileDir) != 0 )
    {
        CfgFileParser->setStringValue(CfgFile.Keys[CONFIG_FILE_KEY_T_FILES], PrefsData->FileDir, strlen(PrefsData->FileDir));
    }
}
