
#include "ToolTip.h"

#include <commctrl.h>


// Description:
//   Creates a tooltip for an item. 
// Parameters:
//   ChildId - identifier of an item.
//   Parent - window handle of the dialog box.
//   Text - string to use as the tooltip text.
// Returns:
//   The handle to the tooltip.
//
HWND ToolTip::forChildId(INT ChildId, HWND Parent, const char* Text)
{
    if ( !ChildId || !Parent || !Text )
    {
        return FALSE;
    }
    // Get the window of the tool.
    HWND child = GetDlgItem(Parent, ChildId);
    
    return ToolTip::forChild(child, Parent, Text);
}

// Description:
//   Creates a tooltip for an item. 
// Parameters:
//   idTool - identifier of an item.
//   Parent - window handle of the dialog box.
//   Text - string to use as the tooltip text.
// Returns:
//   The handle to the tooltip.
//
HWND ToolTip::forChild(HWND Child, HWND Parent, const char* Text)
{
    if ( !Child || !Parent || !Text )
    {
        return NULL;
    }
    
    // Create the tooltip. g_hInst is the global instance handle.
    HWND hwndTip = CreateWindowExA(NULL, TOOLTIPS_CLASS, NULL,
                              WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              CW_USEDEFAULT, CW_USEDEFAULT,
                              Parent, NULL, 
                              NULL, NULL);
    
   if ( !hwndTip )
   {
       return (HWND)NULL;
   }                              
                              
    // Associate the tooltip with the tool.
    TOOLINFOA toolInfo = { 0 };
    toolInfo.cbSize = sizeof(toolInfo);
    toolInfo.hwnd = Parent;
    toolInfo.uFlags = TTF_IDISHWND | TTF_SUBCLASS;
    toolInfo.uId = (UINT_PTR)Child;
    toolInfo.lpszText = (LPSTR)Text;
    SendMessageA(hwndTip, TTM_ADDTOOL, 0, (LPARAM)&toolInfo);

    return hwndTip;
}

// Description:
//   Creates a tooltip for a parent window
// Parameters:
//   Parent - window handle of the parent.
//   Text - string to use as the tooltip text.
// Returns:
//   void
//
void ToolTip::forWindow(HWND Parent, const char* Text)
{
    RECT Rect;
    GetClientRect(Parent, &Rect);
    ToolTip::forRect(Parent, &Rect, Text); 
} 

// Description:
//   Creates a tooltip for an rectangle in a parent window
// Parameters:
//   Parent - window handle of the parent.
//   Text - string to use as the tooltip text.
//   Rect - the desired tooltip sensible rectangle
// Returns:
//   void
//
void ToolTip::forRect(HWND Parent, PRECT Rect, const char* Text)
{
    // Create a tooltip.
    HWND hwndTT = CreateWindowExA(WS_EX_TOPMOST, TOOLTIPS_CLASS, NULL, 
                                 WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP, 
                                 CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, 
                                 Parent, NULL, NULL, NULL);

    SetWindowPos(hwndTT, HWND_TOPMOST, 0, 0, 0, 0, 
                 SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE);

    
    TOOLINFOA ti = { 0 };
    ti.cbSize   = sizeof(TOOLINFO);
    ti.uFlags   = TTF_SUBCLASS;
    ti.hwnd     = Parent;
    ti.hinst    = NULL;
    ti.lpszText = (LPSTR)Text;
    
    // Set up "tool" information. In this case, the "tool" is the entire parent window.
    ti.rect.bottom = Rect->bottom;
    ti.rect.left = Rect->left;
    ti.rect.right = Rect->right;
    ti.rect.top = Rect->top;

    // Associate the tooltip with the "tool" window.
    SendMessageA(hwndTT, TTM_ADDTOOL, 0, (LPARAM) (LPTOOLINFO) &ti); 
} 