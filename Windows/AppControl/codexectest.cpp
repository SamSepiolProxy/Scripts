// HelloMsgBox.cpp
#include <windows.h>

int main()
{
    // Parameters:
    // 1) HWND   hWnd        = NULL        (no owner window)
    // 2) LPCSTR lpText      = "Hello, World!"
    // 3) LPCSTR lpCaption   = "Greetings"
    // 4) UINT   uType       = MB_OK | MB_ICONINFORMATION
    MessageBoxA(
        NULL,
        "Code Exec Test",
        "Code Exec Test",
        MB_OK | MB_ICONINFORMATION
    );

    return 0;
}