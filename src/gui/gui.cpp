#ifdef _DEBUG
#pragma warning( disable : 4100 4101 4102 4189 )
#endif

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
#include "../engine.h"
#include "../guiBridge.h"
#include "../files/Files.h"
#include "../Strings.h"

#include "../utils/ConfigFileParser.h"

#include "dialogs/ConnectionDataDialog.h"

#define MAX_LOADSTRING (0x80)

#define ANONYMOUS ""
#define DEFAULT_IP4 ""
#define DEFAULT_IP6 ""
#define DEFAULT_PORT ""

#define MSG_CMD_FILE "\\file "
#define MSG_CMD_FILE_LN (strlen(MSG_CMD_FILE))


// Global Variables:
HWND MainWindow;
HINSTANCE hInst;                                // current instance
static CHAR szTitle[MAX_LOADSTRING];                  // The title bar text
static CHAR szWindowClass[MAX_LOADSTRING];            // the main window class name

static HWND NameIpt, IpIpt, IpVersionIpt, PortIpt, CertFileIpt, MessageIpt, MessageOpt, StatusOpt, ListenBtn, ConnectBtn, SendBtn;
//HWND FileIpt, ShaOpt;
static HWND SelFileBtn;
static WNDPROC oldMessageIpt;
HWND FilePBar;

#define ERROR_MESSAGE_SIZE (0x200)
static CHAR err_msg[ERROR_MESSAGE_SIZE];

#define HWND_NAME_IPT_IDX           (0x1)
#define HWND_IP_IPT_IDX             (0x2)
#define HWND_PORT_IPT_IDX           (0x3)
#define HWND_CERT_IPT_IDX           (0x4)
#define HWND_CERT_BTN_IDX           (0x5)
#define HWND_MESSAGE_IPT_IDX        (0x6)
#define HWND_MESSAGE_OPT_IDX        (0x7)
#define HWND_CONNECT_BTN_IDX        (0x8)
#define HWND_LISTEN_BTN_IDX         (0x9)
#define HWND_STATUS_OPT_IDX         (0xa)
#define HWND_SEND_BTN_IDX           (0xb)
#define HWND_FILE_PROGRESS_IDX      (0xc)
#define HWND_IP_VERSION_IPT_IDX     (0xd)
#define HWND_FILE_IPT_IDX           (0xe)
#define HWND_FILE_BTN_IDX           (0xf)

static CONNECTION_STATUS ConnectionStatus = CONNECTION_STATUS::STOPPED;
static FILE_TRANSFER_STATUS FileTransferStatus = FILE_TRANSFER_STATUS::STOPPED;
std::mutex cstmtx;
static ULONG ThreadId = 0;
static HANDLE Thread = NULL;

static CHAR ip[MAX_IP_LN];
static CHAR port[MAX_PORT_LN];
static CHAR name[MAX_NAME_LN];
static CHAR CertThumb[SHA1_STRING_BUFFER_LN];
static CHAR LogDir[MAX_PATH];
static CHAR CertDir[MAX_PATH];
static CHAR FileDir[MAX_PATH];
extern ADDRESS_FAMILY family;
static char* pmsg = NULL;
static int type = 0;


static HICON gui_icon_on = NULL;
static HICON gui_icon_off = NULL;
static HICON gui_icon_listen = NULL;

HGLOBAL notify_snd = NULL; 

// Forward declarations of functions included in this code module:
static ATOM MyRegisterClass(HINSTANCE hInstance);
static BOOL InitInstance(HINSTANCE, int);
static LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);

static INT_PTR CALLBACK AboutDialogCB(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK PrefsDialogCB(HWND, UINT, WPARAM, LPARAM);
static INT_PTR CALLBACK ConnectionDataDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);
INT_PTR CALLBACK FTAcceptDialog(HWND, UINT, WPARAM, LPARAM);

static LRESULT onCommand(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);
static LRESULT onCreate(HWND hWnd);
static LRESULT onPaint(HWND hWnd);
static LRESULT onDestroy(HWND hWnd);

static LRESULT onSelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix);
static LRESULT SelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix);

static LRESULT onConnect(HWND hWnd);
static LRESULT onListen(HWND hWnd);
static LRESULT onSend(HWND hWnd);
static VOID stopNetworking();
static DWORD WINAPI ReceiveThread(LPVOID lpParam);
static DWORD WINAPI ListenThread(LPVOID lpParam);

static VOID parseCmdLine(LPSTR lpCmdLine);
static void parseConfigFile();
void fillParamDefaults();

static VOID sayHello();
static VOID setupNetClient();
static VOID stopConnection(HWND hWnd, const char* msg, HWND btn, const char* btnText, HWND otherBtn);
static BOOL loadSound(LPSTR lpName, HGLOBAL* Res);
static LRESULT sendMessage(PCHAR msg, ULONG msg_len);
static LRESULT sendFile(PCHAR msg, ULONG msg_len);
static LRESULT CancelFileTransfer();

ConnectionDataDialog connectionDataDialog;

#define DEFAULT_WINDOW_WIDTH (800)
#define DEFAULT_WINDOW_HEIGHT (530)
#define MIN_WINDOW_WIDTH (600)
#define MIN_WINDOW_HEIGHT (260)
#define DEFAULT_BTN_W (100)
#define DEFAULT_BTN_H (20)
#define PARENT_PADDING (10)
#define IPT_PADDING (10)
#define IPT_H (10)
#define DEFAULT_PROG_BAR_W (100)
#define DEFAULT_PROG_BAR_H (20)
RECT MainRect;
RECT MessageOptRect;
RECT StatusOptRect;
RECT MessageIptRect;

int rows_y[] = { 10, 30, 50, 70, 100, 130, 370, 400, 430 };




int APIENTRY WinMain(
    _In_ HINSTANCE hInstance,
    _In_opt_ HINSTANCE hPrevInstance,
    _In_ LPSTR lpCmdLine,
    _In_ int nCmdShow
)
{
    UNREFERENCED_PARAMETER(hPrevInstance);

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
    LoadStringA(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringA(hInstance, IDC_GUI, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if ( !InitInstance(hInstance, nCmdShow) )
    {
        return 0;
    }
    
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

    ZeroMemory(ip, MAX_IP_LN);
    ZeroMemory(port, MAX_PORT_LN);
    ZeroMemory(name, MAX_NAME_LN);
    //ZeroMemory(CertFile, MAX_PATH);
    ZeroMemory(CertThumb, SHA1_STRING_BUFFER_LN);
    ZeroMemory(LogDir, MAX_PATH);
    ZeroMemory(CertDir, MAX_PATH);
    ZeroMemory(FileDir, MAX_PATH);

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
                strcpy_s(CertThumb, SHA1_STRING_BUFFER_LN, pszOption);

            i++;
            break;

        case 'd':
            if ( pszOption == NULL )
                break;
            
            if ( pszOptionLen < MAX_PATH )
                strcpy_s(CertDir, MAX_PATH, pszOption);

            i++;
            break;

        case 'f':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_PATH ) 
                strcpy_s(FileDir, MAX_PATH, pszOption);

            i++;
            break;

        case 'i':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_IP_LN ) 
                strcpy_s(ip, MAX_IP_LN, pszOption);

            i++;
            break;

        case 'l':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_PATH )
                strcpy_s(LogDir, MAX_PATH, pszOption);            

            i++;
            break;
            
        case 'n':
            if ( pszOption == NULL )
                break;

            if ( pszOptionLen < MAX_NAME_LN ) 
                strcpy_s(name, MAX_NAME_LN, pszOption);

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
                strcpy_s(port, MAX_PORT_LN, pszOption);

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
            }
            else if ( ipv == 6 )
            {
                family = AF_INET6;
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
    if ( port[0] == 0 )
        strcpy_s(port, MAX_PORT_LN, DEFAULT_PORT);

    if ( name[0] == 0 )
        strcpy_s(name, MAX_NAME_LN, ANONYMOUS);

    if ( ip[0] == 0 )
    {
        strcpy_s(ip, MAX_IP_LN, DEFAULT_IP4);
    }

    if ( CertDir[0] == 0 )
    {
        strcpy_s(CertDir, MAX_PATH, ".\\");
    }
    else
    {
        cropTrailingSlash(CertDir);
    }

    if ( LogDir[0] == 0 )
    {
        strcpy_s(LogDir, MAX_PATH, ".\\");
    }
    else
    {
        cropTrailingSlash(LogDir);
    }

    if ( FileDir[0] == 0 )
    {
        strcpy_s(FileDir, MAX_PATH, ".\\");
    }
    else
    {
        cropTrailingSlash(FileDir);
    }
    
    client_setLogDir(LogDir);
    client_setCertDir(CertDir);
    client_setFileDir(FileDir);
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
    wcex.lpszClassName = szWindowClass;
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
    hInst = hInstance; // Store instance handle in our global variable

    LONG ww = DEFAULT_WINDOW_WIDTH;
    LONG wh = DEFAULT_WINDOW_HEIGHT;
    MainRect = { 0, 0, ww, wh };

    MainWindow = CreateWindowExA(
        0,
        szWindowClass,
        szTitle,
        WS_OVERLAPPEDWINDOW | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX,
        CW_USEDEFAULT,
        0,
        MainRect.right - MainRect.left,
        MainRect.bottom - MainRect.top,
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
    
    //DOUBLE cxRate, cyRate; 
    INT newX, newY, newW, newH; 

    if ( rcParent->right < MIN_WINDOW_WIDTH && rcParent->bottom < MIN_WINDOW_HEIGHT )
        return TRUE;

    if ( rcParent->right < MIN_WINDOW_WIDTH )
        ParentW = MIN_WINDOW_WIDTH;
    if ( rcParent->bottom < MIN_WINDOW_HEIGHT )
        ParentH = MIN_WINDOW_HEIGHT;

    if ( idChild == HWND_MESSAGE_OPT_IDX )
        rcChild = &MessageOptRect;
    else if ( idChild == HWND_STATUS_OPT_IDX )
        rcChild = &StatusOptRect;
    else if ( idChild == HWND_MESSAGE_IPT_IDX || HWND_FILE_BTN_IDX || HWND_SEND_BTN_IDX || HWND_FILE_PROGRESS_IDX )
        rcChild = &MessageIptRect;
    else
        return TRUE;

    //cxRate = (DOUBLE)rcParent->right / DEFAULT_WINDOW_WIDTH;
    //cyRate = (DOUBLE)rcParent->bottom / DEFAULT_WINDOW_HEIGHT;

#ifdef DEBUG_PRINT
    std::string s = "left: "+std::to_string(rcParent->left)
        +", top: "+std::to_string(rcParent->top)
        +", right: "+std::to_string(rcParent->right)
        +", bottom: "+std::to_string(rcParent->bottom);
    showStatus(s.c_str());
#endif

    if ( idChild == HWND_MESSAGE_OPT_IDX )
    {
        newX = (INT)(rcChild->left);
        newY = (INT)(rcChild->top);
        newW = (INT)(ParentW - PARENT_PADDING*2);
        newH = (INT)(ParentH - rcChild->top - PARENT_PADDING*3);
    }
    else if ( idChild == HWND_STATUS_OPT_IDX )
    {
        newX = (INT)(rcChild->left);
        newY = (INT)(ParentH - IPT_H*2);
        newW = (INT)(ParentW);
        newH = (INT)(rcChild->bottom);
    }
    else if ( idChild == HWND_MESSAGE_IPT_IDX )
    {
        newX = (INT)(rcChild->left);
        newY = (INT)(rcChild->top);
        newW = (INT)(ParentW - rcChild->left - DEFAULT_BTN_W*2 - PARENT_PADDING - IPT_PADDING*2);
        newH = (INT)(rcChild->bottom);
    }
    else if ( idChild == HWND_FILE_BTN_IDX )
    {
        newX = (INT)(ParentW - DEFAULT_BTN_W - PARENT_PADDING);
        newY = (INT)(rcChild->top);
        newW = (INT)(DEFAULT_BTN_W);
        newH = (INT)(DEFAULT_BTN_H);
    }
    else if ( idChild == HWND_SEND_BTN_IDX )
    {
        newX = (INT)(ParentW - DEFAULT_BTN_W*2 - PARENT_PADDING - IPT_PADDING);
        newY = (INT)(rcChild->top);
        newW = (INT)(DEFAULT_BTN_W);
        newH = (INT)(DEFAULT_BTN_H);
    }
    else if ( idChild == HWND_FILE_PROGRESS_IDX )
    {
        newX = (INT)(ParentW - DEFAULT_PROG_BAR_W - PARENT_PADDING);
        newY = (INT)(rcChild->top - DEFAULT_PROG_BAR_H);
        newW = (INT)(DEFAULT_PROG_BAR_W);
        newH = (INT)(DEFAULT_PROG_BAR_H);
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

    switch ( wmId )
    {
    case HWND_CONNECT_BTN_IDX:
        result = onConnect(hWnd);
        break;

    case HWND_LISTEN_BTN_IDX:
        result = onListen(hWnd);
        break;

    case HWND_FILE_BTN_IDX:
        result = onSelectFile(hWnd, FOS_FORCEFILESYSTEM, MessageIpt, MSG_CMD_FILE);
        break;

    case HWND_SEND_BTN_IDX:
        result = onSend(hWnd);
        break;

    case IDM_ABOUT:
        DialogBoxA(hInst, MAKEINTRESOURCEA(IDD_ABOUT_BOX), hWnd, AboutDialogCB);
        break;

    case IDM_PREFS:
        DialogBoxA(hInst, MAKEINTRESOURCEA(IDD_PREFS_BOX), hWnd, PrefsDialogCB);
        break;

    case IDM_CONN_DATA:
        DialogBoxA(hInst, MAKEINTRESOURCEA(IDD_CONN_DATA_BOX), hWnd, ConnectionDataDialogCB);
        break;

    //case WM_CTLCOLORSTATIC:
    //    SetWindowTextA(CertFileIpt, "WM_CTLCOLORSTATIC");
    //    break;

    case IDM_EXIT:
        DestroyWindow(hWnd);
        break;

    default:
        return DefWindowProcA(hWnd, message, wParam, lParam);
    }

    return result;
}

LRESULT onDestroy(HWND hWnd)
{
    LRESULT result = 0;
    UNREFERENCED_PARAMETER(hWnd);

    if ( Thread != NULL )
        CloseHandle(Thread);
    stopNetworking();

    PostQuitMessage(0);
    
    DestroyIcon(gui_icon_off);
    DestroyIcon(gui_icon_on);
    DestroyIcon(gui_icon_listen);
    FreeResource(notify_snd);

    if ( pmsg )
        delete[] pmsg;

    return result;
}


// Message handler for about box.
INT_PTR CALLBACK AboutDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch ( message )
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if ( LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL )
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

 //Message handler for prefs box.
INT_PTR CALLBACK PrefsDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);

    switch ( message )
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if ( LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL )
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

 //Message handler for connection data
INT_PTR CALLBACK ConnectionDataDialogCB(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    return connectionDataDialog.openCb(hDlg, message, wParam, lParam);
}

// Message handler for prefs box.
INT_PTR CALLBACK FTAcceptDialog(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    char* base_name;

    switch ( message )
    {
    case WM_INITDIALOG:
        base_name = (char*)lParam;
        SetDlgItemTextA(hDlg, IDC_ACCEPT_FILE_IPT, base_name);
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if ( LOWORD(wParam) == IDYES || LOWORD(wParam) == IDNO || LOWORD(wParam) == IDCANCEL )
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

LRESULT CALLBACK subEditProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
        case WM_CHAR :
            switch ( wParam ) {
                case VK_RETURN :
                    onSend(hWnd);
                    return 0;
            }
        default:
            break;
    }
    return CallWindowProc(oldMessageIpt, hWnd, msg, wParam, lParam);
}
//#include "Richedit.h"
//#include "commctrl.h"


LRESULT onCreate(HWND hWnd)
{
    LRESULT result = 0;

    int ipt_x = 85;
    int ipt_x2 = 485;
    int ipt_w1 = 100;
    int ipt_w2 = 300;
    int ipt_w3 = 400;
    int ipt_w4 = 500;
    int ipt_h = DEFAULT_BTN_H;
    int btn_w = DEFAULT_BTN_W;
    int btn_h = 20;
    int send_btn_x = 585;
    int file_btn_x = send_btn_x + btn_w + 10;
    int msg_ipt_w = ipt_w4;
    int msg_box_w = 600;
    int msg_box_h = 230;

    NameIpt = CreateWindowA(
        "EDIT",
        (name==NULL)?ANONYMOUS:name,
        WS_BORDER | WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        ipt_x, rows_y[0], ipt_w1, ipt_h,
        hWnd, (HMENU)HWND_NAME_IPT_IDX, NULL, NULL
    );

    IpIpt = CreateWindowA(
        "EDIT",
        (ip==NULL)?"127.0.0.1":ip,
        WS_BORDER | WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        ipt_x, rows_y[1], ipt_w2, ipt_h,
        hWnd, (HMENU)HWND_IP_IPT_IDX, NULL, NULL
    );

    IpVersionIpt = CreateWindowA(
        "EDIT",
        (family==AF_INET)?"4":"6",
        WS_BORDER | WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        ipt_x2, rows_y[1], ipt_w1, ipt_h,
        hWnd, (HMENU)HWND_IP_IPT_IDX, NULL, NULL
    );

    PortIpt = CreateWindowA(
        "EDIT",
        (port==NULL)?"8080":port,
        WS_BORDER | WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        ipt_x, rows_y[2], ipt_w1, ipt_h,
        hWnd, (HMENU)HWND_PORT_IPT_IDX, NULL, NULL
    );

    CertFileIpt = CreateWindowA(
        "EDIT",
        (CertThumb[0]==0)?"":CertThumb,
        WS_BORDER | WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL,
        ipt_x, rows_y[3], ipt_w3, ipt_h,
        hWnd, (HMENU)HWND_CERT_IPT_IDX, NULL, NULL
    );
    
    //MessageIpt = CreateWindowA(
    //    "EDIT",
    //    "",
    //    WS_BORDER | WS_CHILD | WS_VISIBLE | WS_GROUP | ES_AUTOHSCROLL,
    //    ipt_x, rows_y[4], msg_ipt_w, ipt_h,
    //    hWnd, (HMENU)HWND_MESSAGE_IPT_IDX, NULL, NULL
    //);
    MessageIptRect.left = ipt_x;
    MessageIptRect.top = rows_y[4];
    MessageIptRect.right = msg_ipt_w;
    MessageIptRect.bottom = ipt_h;
    MessageIpt = CreateWindowExA(
        0, // WS_EX_CLIENTEDGE
        "EDIT", 
        (pmsg)?pmsg:"", 
        WS_BORDER | WS_CHILD | WS_VISIBLE  | ES_AUTOHSCROLL | ES_MULTILINE,
        MessageIptRect.left, MessageIptRect.top, MessageIptRect.right, MessageIptRect.bottom,
        hWnd, 
        (HMENU)HWND_MESSAGE_IPT_IDX, 
        GetModuleHandle(NULL), 
        NULL
    );
    oldMessageIpt = (WNDPROC)SetWindowLongPtr(MessageIpt, GWLP_WNDPROC, (LONG_PTR)subEditProc);

    SendBtn = CreateWindowA(
        "BUTTON",
        "Send",
        WS_BORDER | WS_CHILD | WS_VISIBLE,
        send_btn_x, rows_y[4], btn_w, btn_h,
        hWnd, (HMENU)HWND_SEND_BTN_IDX, NULL, NULL
    );

    //FileIpt = CreateWindowA(
    //    "EDIT",
    //    "",
    //    WS_BORDER | WS_CHILD | WS_VISIBLE  | ES_AUTOHSCROLL,
    //    ipt_x, rows_y[5], ipt_w4, ipt_h,
    //    hWnd, (HMENU)HWND_FILE_IPT_IDX, NULL, NULL
    //);

    SelFileBtn = CreateWindowA(
        "BUTTON",
        FILE_BTN_SELECT_STR,
        WS_BORDER | WS_CHILD | WS_VISIBLE,
        file_btn_x, rows_y[4], btn_w, btn_h,
        hWnd, (HMENU)HWND_FILE_BTN_IDX, NULL, NULL
    );
     
    //LoadLibrary("Msftedit.dll");
    //    MessageOpt = CreateWindowExA(0, "RICHEDIT50W", "Type here",
    //    WS_BORDER | WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY, 
    //    ipt_x, rows_y[6], msg_box_w, msg_box_h,
    //    hWnd, (HMENU)HWND_MESSAGE_OPT_IDX, hInst, NULL);
    MessageOptRect.left = PARENT_PADDING;
    MessageOptRect.top = rows_y[5];
    MessageOptRect.right = msg_box_w;
    MessageOptRect.bottom = msg_box_h;
    MessageOpt = CreateWindowA(
        "EDIT",
        "",
        WS_BORDER | WS_CHILD | WS_VISIBLE | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
        MessageOptRect.left, MessageOptRect.top, MessageOptRect.right, MessageOptRect.bottom,
        hWnd, (HMENU)HWND_MESSAGE_OPT_IDX, NULL, NULL
    );

    StatusOptRect.left = 0;
    StatusOptRect.top = DEFAULT_WINDOW_HEIGHT - 20;
    StatusOptRect.right = DEFAULT_WINDOW_WIDTH;
    StatusOptRect.bottom = ipt_h;
    StatusOpt = CreateWindowA(
        "EDIT",
        "",
        WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL | ES_READONLY,
        StatusOptRect.left, StatusOptRect.top, StatusOptRect.right, StatusOptRect.bottom,
        hWnd, (HMENU)HWND_STATUS_OPT_IDX, NULL, NULL
    );

    ListenBtn = CreateWindowExA(
        0,
        "BUTTON",
        "Listen",
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        send_btn_x, rows_y[1], btn_w, btn_h,
        hWnd, (HMENU)HWND_LISTEN_BTN_IDX, NULL, NULL
    );

    ConnectBtn = CreateWindowExA(
        0,
        "BUTTON",
        "Connect",
        WS_VISIBLE | WS_CHILD | WS_BORDER,
        send_btn_x, rows_y[2], btn_w, btn_h,
        hWnd, (HMENU)HWND_CONNECT_BTN_IDX, NULL, NULL
    );

    FilePBar = CreateWindowExA(
                0, 
                PROGRESS_CLASS, 
                (LPTSTR) NULL, 
                WS_CHILD | WS_VISIBLE, 
                file_btn_x, rows_y[5], DEFAULT_PROG_BAR_W, DEFAULT_PROG_BAR_H,
                hWnd, 
                (HMENU)HWND_FILE_PROGRESS_IDX, 
                GetModuleHandle(NULL), 
                NULL
            );

    SendMessage(FilePBar, PBM_SETRANGE, 0, MAKELPARAM(0, 100));
    ShowWindow(FilePBar, SW_HIDE);
    
    setStatusOutput(StatusOpt);
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
    CHAR name_lbl[] = "User name";
    CHAR ip_lbl[] = "IP";
    CHAR ipv_lbl[] = "Version";
    CHAR port_lbl[] = "Port";
    CHAR cert_lbl[] = "Cert thumb";
    CHAR message_lbl[] = "Message";

    int lbl_x = 10;
    int lbl_x2 = 425;

    PAINTSTRUCT ps;
    HDC hdc = BeginPaint(hWnd, &ps);

    TextOutA(hdc, lbl_x, rows_y[0], name_lbl, (int)strlen(name_lbl));

    TextOutA(hdc, lbl_x, rows_y[1], ip_lbl, (int)strlen(ip_lbl));

    TextOutA(hdc, lbl_x2, rows_y[1], ipv_lbl, (int)strlen(ipv_lbl));
    
    TextOutA(hdc, lbl_x, rows_y[2], port_lbl, (int)strlen(port_lbl));

    TextOutA(hdc, lbl_x, rows_y[3], cert_lbl, (int)strlen(cert_lbl));

    TextOutA(hdc, lbl_x, rows_y[4], message_lbl, (int)strlen(message_lbl));

    EndPaint(hWnd, &ps);
    
    return result;
}

__forceinline
ADDRESS_FAMILY deriveFamily(PCHAR ip_, int n)
{
    if ( n >= MAX_IP_LN )
        return 0;
    
    if ( n == 0 )
    {
        int ipv_len = GetWindowTextLengthA(IpVersionIpt) + 1;
        if ( ipv_len > 2 )
        {
            showStatus("Wrong IP Version size!");
            return 0;
        }
        char ipv_str[2];
        GetWindowTextA(IpVersionIpt, ipv_str, ipv_len);
        int ipv = (int)strtoul(ipv_str, NULL, 0);
        if ( ipv == 4 )
            return AF_INET;
        else if ( ipv == 6 )
            return AF_INET6;
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
    int ip_len = GetWindowTextLengthA(IpIpt) + 1;
    if ( ip_len > 1 && ip_len <= MAX_IP_LN )
        GetWindowTextA(IpIpt, ip, ip_len); 
    else
    {
        ip[0] = 0;
        ip_len = 1;
        showStatus("Wrong IP size!");
    }
    family = deriveFamily(ip, ip_len-1);
        
    int port_len = GetWindowTextLengthA(PortIpt) + 1;
    if ( port_len > 1 && port_len <= MAX_PORT_LN )
        GetWindowTextA(PortIpt, port, port_len);
    else
    {
        port[0] = 0;
        showStatus("Wrong port size!");
    }

    int name_len = GetWindowTextLengthA(NameIpt) + 1;
    if ( name_len > 1 && name_len <= MAX_NAME_LN )
        GetWindowTextA(NameIpt, name, name_len);
    else
    {
        strcpy_s(name, MAX_NAME_LN, ANONYMOUS);
        showStatus("Wrong name size!");
    }

    int cert_len = GetWindowTextLengthA(CertFileIpt) + 1;
    if ( cert_len > 1 && cert_len <= MAX_PATH )
        GetWindowTextA(CertFileIpt, CertThumb, cert_len);
    else
    {
        CertThumb[0] = 0;
        showStatus("Wrong cert name size!");
    }

    client_setNick(name);
}

void enableConnectedControls(HWND btn)
{
    SendMessageA(NameIpt, EM_SETREADONLY, FALSE, NULL);
    SendMessageA(IpIpt, EM_SETREADONLY, FALSE, NULL);
    SendMessageA(PortIpt, EM_SETREADONLY, FALSE, NULL);
    SendMessageA(IpVersionIpt, EM_SETREADONLY, FALSE, NULL);
    SendMessageA(CertFileIpt, EM_SETREADONLY, FALSE, NULL);
    EnableWindow(btn, TRUE);
}

void disableConnectedControls(HWND btn)
{
    SendMessageA(NameIpt, EM_SETREADONLY, TRUE, NULL);
    SendMessageA(IpIpt, EM_SETREADONLY, TRUE, NULL);
    SendMessageA(PortIpt, EM_SETREADONLY, TRUE, NULL);
    SendMessageA(IpVersionIpt, EM_SETREADONLY, TRUE, NULL);
    SendMessageA(CertFileIpt, EM_SETREADONLY, TRUE, NULL);
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
        showStatus("Already in listening mode, can't connect at the same time!");

        return 0;
    }

    if ( ConnectionStatus == CONNECTION_STATUS::STOPPED )
    {
        if ( Thread != NULL )
        {
            showStatus("ERROR: Thread not NULL");
            return -1;
        }
        Thread = NULL;
        ThreadId = 0;

        setupNetClient();

        result = initClient(ip, port, family, CertThumb);
        if ( result != 0 )
        {
            sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Connecting failed: 0x%X", (INT)result);
            showStatus(err_msg);
            goto clean;
        }

        Thread = CreateThread(
            NULL,                   // default security attributes
            0,                      // use default stack size  
            ReceiveThread,       // thread function name
            hWnd,        // argument to thread function 
            0,           // use default creation flags 
            &ThreadId    // returns the thread identifier 
        );
        if ( Thread == NULL )
        {
            showStatus("Creating receive thread failed!");
            stopConnection(hWnd, "Disconnected", ConnectBtn, "Connect", ListenBtn);
            goto clean;
        }
        CloseHandle(Thread);
        Thread = NULL;
        
        disableConnectedControls(ListenBtn);
        showStatus("Connected");
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

    initLog("server");

    if ( ConnectionStatus == CONNECTION_STATUS::STOPPING )
        return 0;

    if ( ConnectionStatus == CONNECTION_STATUS::CONNECTED )
    {
        showStatus("Already in connected mode, can't listen at the same time!");

        return 0;
    }

    if ( ConnectionStatus == CONNECTION_STATUS::STOPPED )
    {
        if ( Thread != NULL )
        {
            showStatus("ERROR: Thread not NULL");
            return -1;
        }
        Thread = NULL;
        ThreadId = 0;

        setupNetClient();

        result = initServer(ip, port, family, CertThumb);
        if ( result != 0 )
        {
            sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Listening failed: 0x%X", (INT)result);
            showStatus(err_msg);
            goto clean;
        }

        Thread = CreateThread(
            NULL,         // default security attributes
            0,            // use default stack size  
            ListenThread, // thread function name
            hWnd,        // argument to thread function 
            0,           // use default creation flags 
            &ThreadId    // returns the thread identifier 
        );
        if ( Thread == NULL )
        {
            showStatus("Creating listen thread failed!");
            stopConnection(hWnd, "Deaf", ListenBtn, "Listen", ConnectBtn);
            goto clean;
        }
        CloseHandle(Thread);
        Thread = NULL;
        
        disableConnectedControls(ConnectBtn);
        SetWindowTextA(ListenBtn, "Stop");
        showStatus("Listening");
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
        showStatus("Type a message first!");
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

    showStatus("Sending...");

    r = client_sendMessage(msg, msg_len);
    if ( (ULONG)r == SCHAT_ERROR_INVALID_SOCKET )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Not connected yet!");
        showStatus(err_msg);
    }
    else if ( (ULONG)r != 0 )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Send error: 0x%X", (ULONG)r);
        showStatus(err_msg);
    }
    else
    {
        SetWindowTextA(MessageIpt, "");
        showStatus("");
    }

    return r;
}

LRESULT sendFile(PCHAR msg, ULONG msg_len)
{
    LRESULT r = 0;

    showStatus("Sending...");

    if ( msg_len <= MSG_CMD_FILE_LN+1 )
    {
        showStatus("Path too short!");
        return -1;
    }

    PCHAR path = &msg[MSG_CMD_FILE_LN];
    ULONG path_len = (ULONG)strlen(path);
    
    if ( path_len < 2 )
    {
        showStatus("Path too short!");
        return -1;
    }

    r = client_sendFile(path, path_len, ip, port, family);
    if ( (ULONG)r == SCHAT_ERROR_INVALID_SOCKET )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Not connected yet!");
        showStatus(err_msg);
    }
    else if ( (ULONG)r != 0 )
    {
        sprintf_s(err_msg, ERROR_MESSAGE_SIZE, "Send file error : 0x%X", (ULONG)r);
        showStatus(err_msg);
    }
    else
    {
        SetWindowTextA(MessageIpt, "");
        showStatus("");
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
DWORD WINAPI ReceiveThread(LPVOID lpParam)
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
    showStatus(msg);
    SetWindowTextA(btn, btnText);

    enableConnectedControls(otherBtn);
    //SendMessageA(NameIpt, EM_SETREADONLY, FALSE, NULL);
    //EnableWindow(otherBtn, TRUE);

    Thread = NULL;
    ThreadId = 0;

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

    showStatus("Stopping...");
    cleanClient();
    showStatus("Stopped");
    
    cstmtx.lock();
    ConnectionStatus = CONNECTION_STATUS::STOPPED;
    cstmtx.unlock();
}

LRESULT onSelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix)
{
    if ( FileTransferStatus == FILE_TRANSFER_STATUS::STOPPED )
    {
        return SelectFile(hWnd, flags, output, prefix);
    }
    else if ( FileTransferStatus == FILE_TRANSFER_STATUS::ACTIVE )
    {
        return CancelFileTransfer();
    }
    return 0;
}

//LRESULT SelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix)
//{
//    LRESULT r = 0;
//
//    OPENFILENAME ofn;       // common dialog box structure
//    char szFile[MAX_PATH];       // buffer for file name
//
//    // Initialize OPENFILENAME
//    ZeroMemory(&ofn, sizeof(ofn));
//    ofn.lStructSize = sizeof(ofn);
//    ofn.hwndOwner = hWnd;
//    ofn.lpstrFile = szFile;
//    // Set lpstrFile[0] to '\0' so that GetOpenFileName does not 
//    // use the contents of szFile to initialize itself.
//    ofn.lpstrFile[0] = '\0';
//    ofn.nMaxFile = sizeof(szFile);
//    ofn.lpstrFilter = "All\0*.*\0";
//    ofn.nFilterIndex = 0;
//    ofn.lpstrFileTitle = NULL;
//    ofn.nMaxFileTitle = 0;
//    ofn.lpstrInitialDir = NULL;
//    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
//
//    (flags);
//    // Display the Open dialog box. 
//    if ( GetOpenFileName(&ofn) == TRUE )
//    {
//        if ( prefix != NULL && prefix[0] != 0 )
//        {
//            size_t value_size = strlen(ofn.lpstrFile)+7;
//            char* value = new char[value_size];
//            sprintf_s(value, value_size, "%s%s", prefix, ofn.lpstrFile);
//            value[value_size-1] = 0;
//            SetWindowTextA(output, value);
//            delete[] value;
//        }
//        else
//        {
//            SetWindowTextA(output, ofn.lpstrFile);
//        }
//    }
//
//    return r;
//}
// Only appears after a large file has been sent.
// VERIFIER STOP 0000000000000350: pid 0x2AE8: Unloading DLL that allocated TLS index that was not freed. 
//
//    000000000047ABBA : TLS index
//    00007FFEA0AB5EE3 : Address of the code that allocated this TLS index.
//    00000207945E7FD8 : DLL name address. Use du to dump it.
//    00007FFEA0AB0000 : DLL base address.
//
// dlnashext!wil::init_once_nothrow<<lambda_ba621665f78b7b7f3bfc8a7498684c3d> >
#include "CDialogEventHandler.h"
LRESULT SelectFile(HWND hWnd, DWORD flags, HWND output, PCZZSTR prefix)
{
    UNREFERENCED_PARAMETER(hWnd);

    DWORD dwCookie = 0;
    BOOL bCookie = FALSE;
    DWORD dwFlags = 0;
    IShellItem *psiResult = NULL;
    PWSTR pszFilePath = NULL;
    IFileDialogEvents *pfde = NULL;
    IFileDialog *pfd = NULL;

    // CoCreate the File Open Dialog object.
    HRESULT hr = CoCreateInstance(CLSID_FileOpenDialog, 
                      NULL, 
                      CLSCTX_INPROC_SERVER, 
                      IID_PPV_ARGS(&pfd));
    if ( FAILED(hr) )
        return hr;

    // Create an event handling object, and hook it up to the dialog.
    hr = CDialogEventHandler_CreateInstance(IID_PPV_ARGS(&pfde));
    if ( FAILED(hr) )
        goto clean;

    // Hook up the event handler.
    hr = pfd->Advise(pfde, &dwCookie);
    if ( FAILED(hr) )
        goto clean;
    bCookie = TRUE;

    // Set the options on the dialog.
    // Before setting, always get the options first in order 
    // not to override existing options.
    hr = pfd->GetOptions(&dwFlags);
    if ( FAILED(hr) )
        goto clean;

    // In this case, get shell items only for file system items.
    hr = pfd->SetOptions(dwFlags | flags);
    if ( FAILED(hr) )
        goto clean;

    // Set the file types to display only. 
    // Notice that this is a 1-based array.
    //hr = pfd->SetFileTypes(ARRAYSIZE(c_rgSaveTypes), c_rgSaveTypes);
    //if ( FAILED(hr) )
    //    goto clean;
    // 
    // Set the selected file type index to Word Docs for this example.
    //hr = pfd->SetFileTypeIndex(INDEX_WORDDOC);
    //if ( FAILED(hr) )
    //    goto clean;
    // 
    // Set the default extension to be ".doc" file.
    //hr = pfd->SetDefaultExtension(L"doc;docx");
    //if ( FAILED(hr) )
    //    goto clean;
    
    // Show the dialog
    hr = pfd->Show(NULL);
    if ( FAILED(hr) )
        goto clean;
     
    // Obtain the result once the user clicks 
    // the 'Open' button.
    // The result is an IShellItem object.
    hr = pfd->GetResult(&psiResult);
    if ( FAILED(hr) )
        goto clean;

    // We are just going to print out the 
    // name of the file for sample sake.
    hr = psiResult->GetDisplayName(SIGDN_FILESYSPATH, &pszFilePath);
    if ( FAILED(hr) )
        goto clean;

    if ( output != NULL )
    {
        if ( prefix != NULL && prefix[0] != 0 )
        {
            size_t value_size = wcslen(pszFilePath)+7;
            wchar_t* value = new wchar_t[value_size];
            swprintf_s(value, value_size, L"%hs%s", prefix, pszFilePath);
            value[value_size-1] = 0;
            SetWindowTextW(output, value);
            delete[] value;
        }
        else
        {
            SetWindowTextW(output, pszFilePath);
        }
    }
    //TaskDialog(NULL,
    //           NULL,
    //           L"CommonFileDialogApp",
    //           pszFilePath,
    //           NULL,
    //           TDCBF_OK_BUTTON,
    //           TD_INFORMATION_ICON,
    //           NULL);

clean:
    if ( pszFilePath != NULL )
        CoTaskMemFree(pszFilePath);
    if ( psiResult != NULL )
        psiResult->Release();
    if ( bCookie )
        pfd->Unadvise(dwCookie);
    if ( pfde != NULL )
        pfde->Release();
    if ( pfd != NULL )
        pfd->Release();

    return hr;
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
    o += sprintf_s(&hello[o], GUI_HELLO_MSG_LN - o, "Compiled: %s -- %s\r\n\r\n", COMPILE_DATA, COMPILE_TIME);

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
    hResInfo = FindResourceA(hInst, lpName, "WAVE"); 
    if (hResInfo == NULL) 
        return FALSE; 
 
    // Load the WAVE resource. 
    *Res = LoadResource((HMODULE)hInst, (HRSRC)hResInfo); 
    if ( *Res == NULL )
        return FALSE; 
 
    return TRUE; 
} 

void parseConfigFile()
{
    CHAR path[MAX_PATH];
    const CHAR* config_name = ".config";
    size_t conifg_name_ln = strlen(config_name);
    ULONG path_ln = GetFullPathNameA(config_name, MAX_PATH, path, NULL);
    if ( path_ln == 0 || path_ln == MAX_PATH )
    {
        return;
    }
    path[path_ln] = 0;
    
    std::vector<std::string> keys = {
        "ip", 
        "port", 
        "ip version",
        "user name", 
        "user cert thumb", 
        "log files dir", 
        "cert files dir", 
        "transfered files dir"

    };
    ConfigFileParser p(keys, '#');
    bool s = p.run(path);
    if ( !s )
        return;


    std::string tempStr;
    std::uint16_t tempShrt;
    
    if ( ip[0] == 0 )
    {
        tempStr = p.getStringValue(keys[0], MAX_IP_LN-1, "");
        strcpy_s(ip, MAX_IP_LN, &tempStr[0]);
    }

    if ( port[0] == 0 )
    {
        tempStr = p.getStringValue(keys[1], MAX_PORT_LN-1, "");
        strcpy_s(port, MAX_PORT_LN, &tempStr[0]);
    }

    if ( family == AF_UNSPEC )
    {
        tempShrt = p.getUInt16Value(keys[2], AF_UNSPEC);
        
        if ( tempShrt == 4 )
        {
            family = AF_INET;
        }
        else if ( tempShrt == 6 )
        {
            family = AF_INET6;
        }
    }

    if ( name[0] == 0 )
    {
        tempStr = p.getStringValue(keys[3], MAX_NAME_LN-1, "");
        strcpy_s(name, MAX_NAME_LN, &tempStr[0]);
    }

    if ( CertThumb[0] == 0 )
    {
        tempStr = p.getStringValue(keys[4], SHA1_STRING_BUFFER_LN-1, "");
        strcpy_s(CertThumb, SHA1_STRING_BUFFER_LN, &tempStr[0]);
    }

    if ( LogDir[0] == 0 )
    {
        tempStr = p.getStringValue(keys[5], MAX_PATH-1, "");
        strcpy_s(LogDir, MAX_PATH, &tempStr[0]);
        cropTrailingSlash(LogDir);
    }

    if ( CertDir[0] == 0 )
    {
        tempStr = p.getStringValue(keys[6], MAX_PATH-1, "");
        strcpy_s(CertDir, MAX_PATH, &tempStr[0]);
        cropTrailingSlash(CertDir);
    }

    if ( FileDir[0] == 0 )
    {
        tempStr = p.getStringValue(keys[7], MAX_PATH-1, "");
        strcpy_s(FileDir, MAX_PATH, &tempStr[0]);
        cropTrailingSlash(FileDir);
    }
}
