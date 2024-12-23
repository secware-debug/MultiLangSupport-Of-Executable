#define WINVER 0x0600 // For Windows Vista and later
#define _WIN32_WINNT 0x0600

#define _CRT_SECURE_NO_WARNINGS

// Your code here
#include "version.h"
#include <stdio.h>
//#include <string>
//#include <iostream>
//#include <stdlib.h>
//#include <winsock2.h>
//#include <cstdio>
//#include <fstream>
//#include <sstream>
//#include <iomanip>
#include <imm.h>
//#include <DbgHelp.h>

#pragma comment(lib, "Imm32.lib")

//#pragma comment(lib, "Ws2_32.lib")
//#pragma comment(lib, "dbghelp.lib")

/*
void write_log(const char* format, ...) {
	FILE* log_file = fopen("hook_log.txt", "a");  // Open in append mode
	if (log_file == NULL) {
		perror("Error opening log file");
		return;
	}

	// Handle variable arguments for formatted logging
	va_list args;
	va_start(args, format);
	vfprintf(log_file, format, args);
	va_end(args);

	// Add a newline to separate log entries

	fclose(log_file);  // Close the file
}*/


typedef HIMC(WINAPI* ImmAssociateContext_t)(HWND, HIMC);

// Pointer to the original API
ImmAssociateContext_t TrueImmAssociateContext = nullptr;

HIMC WINAPI HookedImmAssociateContext(HWND hWnd, HIMC hImc) {
	// Log the event for debugging
	//OutputDebugStringA("ImmAssociateContext called!\n");

	// Check if HIMC is being set to NULL (disabling the IME)
	if (hImc == NULL) {
		// Get the current keyboard layout
		HKL keyboardLayout = GetKeyboardLayout(0); // Get the current keyboard layout
		WORD primaryLanguage = LOWORD(keyboardLayout);

		// Check if the language is Chinese (0x0804 for Simplified, 0x0404 for Traditional)
		if (primaryLanguage == MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_SIMPLIFIED) ||
			primaryLanguage == MAKELANGID(LANG_CHINESE, SUBLANG_CHINESE_TRADITIONAL)) {
		//	OutputDebugStringA("Attempt to disable Chinese input method blocked.\n");

			// Return the current HIMC for the window to ensure it is not disabled
			HIMC currentHimc = ImmGetContext(hWnd);
			return currentHimc; // Ensure that the IME remains associated
		}
	}

	// Call the original API to proceed as normal
	if (TrueImmAssociateContext) {
		return TrueImmAssociateContext(hWnd, hImc);
	}

	return NULL; // If original function is not available, return NULL
}

/*

typedef BOOL(WINAPI* ImmAssociateContextEx_t)(HWND, HIMC, DWORD);
ImmAssociateContextEx_t TrueImmAssociateContextEx = nullptr;

BOOL WINAPI HookedImmAssociateContextEx(HWND hWnd, HIMC hImc, DWORD dwFlags) {
	// Add custom logic here
	OutputDebugStringA("ImmAssociateContextEx called!\n");

	// Call the original function
	if (TrueImmAssociateContextEx) {
		return TrueImmAssociateContextEx(hWnd, hImc, dwFlags);
	}

	return FALSE; // Default return if the original function is not available
}*/


typedef int(WINAPI* WideCharToMultiByte_t)(
	UINT CodePage,
	DWORD dwFlags,
	LPCWCH lpWideCharStr,
	int cchWideChar,
	LPSTR lpMultiByteStr,
	int cbMultiByte,
	LPCSTR lpDefaultChar,
	LPBOOL lpUsedDefaultChar
	);

WideCharToMultiByte_t TrueWideCharToMultiByte = NULL;

// Hooked function
int WINAPI HookedWideCharToMultiByte(
	UINT CodePage,
	DWORD dwFlags,
	LPCWCH lpWideCharStr,
	int cchWideChar,
	LPSTR lpMultiByteStr,
	int cbMultiByte,
	LPCSTR lpDefaultChar,
	LPBOOL lpUsedDefaultChar
) {
	// Example hook logic
	// OutputDebugStringA("WideCharToMultiByte Hooked");  // Log hook
	/*if (lpWideCharStr) {
		char debugMsg[256];
		snprintf(debugMsg, sizeof(debugMsg), "WidChartoMultiByte! Input String: %s, flag: %d, CodePage: %d", lpMultiByteStr, dwFlags, CodePage);
		OutputDebugStringA(debugMsg);
	}*/

	UINT newCodePage = CodePage;
	if (CodePage == 949) newCodePage = 65001; // Example modification

	// Call the original function
	return TrueWideCharToMultiByte(
		newCodePage,
		dwFlags,
		lpWideCharStr,
		cchWideChar,
		lpMultiByteStr,
		cbMultiByte,
		lpDefaultChar,
		lpUsedDefaultChar
	);
}

typedef int(WINAPI* MultiByteToWideChar_t)(
	UINT CodePage,
	DWORD dwFlags,
	LPCCH lpMultiByteStr,
	int cbMultiByte,
	LPWSTR lpWideCharStr,
	int cchWideChar
	);

MultiByteToWideChar_t TrueMultiByteToWideChar = NULL;

// Hooked function
int WINAPI HookedMultiByteToWideChar(
	UINT CodePage,
	DWORD dwFlags,
	LPCCH lpMultiByteStr,
	int cbMultiByte,
	LPWSTR lpWideCharStr,
	int cchWideChar
) {
	// Example hook logic
	//OutputDebugStringA("MultiByteToWideChar Hooked");  // Log hook
	/*if (lpMultiByteStr) {
		char debugMsg[256];
		snprintf(debugMsg, sizeof(debugMsg), "MultiToW! Input String: %s, flag: %d, CodePage: %d", lpMultiByteStr, dwFlags, CodePage);
		OutputDebugStringA(debugMsg);
	}*/
	UINT newCodePage = CodePage;
	if (CodePage == 949) newCodePage = 65001; // 949: Ko_encoding_code, 65001: UTF8_encoding_code
	// Call the original function
	return TrueMultiByteToWideChar(
		newCodePage,
		dwFlags,
		lpMultiByteStr,
		cbMultiByte,
		lpWideCharStr,
		cchWideChar
	);
}

static BOOL InstallHook(LPCSTR dll, LPCSTR function, LPVOID* originalFunction, LPVOID hookedFunction)
{
	LoadLibraryA(dll);
	HMODULE module = GetModuleHandleA(dll);
	*originalFunction = (LPVOID)GetProcAddress(module, function);

	if (*originalFunction)
	{
		DetourAttach(originalFunction, hookedFunction);
		return true;
	}
	return false;
}
/*
typedef int(WINAPI* MessageBoxA_t)(
	HWND hWnd,
	LPCSTR lpText,
	LPCSTR lpCaption,
	UINT uType
	);

MessageBoxA_t TrueMessageBoxA = NULL;

int WINAPI HookedMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	// Custom logic before calling the original function
	OutputDebugStringA("MessageBoxA Hooked"); // Example hook action
	return TrueMessageBoxA(hWnd, lpText, lpCaption, uType);  // Call the original function
}

typedef int(WINAPI* DrawTextA_t)(
	HDC hdc,
	LPCSTR lpchText,
	int cchText,
	LPRECT lprc,
	UINT format
	);

DrawTextA_t TrueDrawTextA = NULL;

int WINAPI HookedDrawTextA(HDC hdc, LPCSTR lpchText, int cchText, LPRECT lprc, UINT format) {
	if (lpchText) {
		OutputDebugStringA("Hooked DrawTextA to correctly handle Unicode output!");

		// Convert ANSI string (lpchText) to wide-character string (LPCWSTR)
		int len = MultiByteToWideChar(CP_ACP, 0, lpchText, cchText, NULL, 0);
		if (len > 0) {
			// Allocate memory for wide-character string
			WCHAR* lpchTextW = (WCHAR*)malloc((len + 1) * sizeof(WCHAR));
			if (lpchTextW) {
				// Perform the conversion
				MultiByteToWideChar(CP_ACP, 0, lpchText, cchText, lpchTextW, len);
				lpchTextW[len] = L'\0'; // Null-terminate the wide string

				// Call DrawTextW to display the Unicode string
				int result = DrawTextW(hdc, lpchTextW, -1, lprc, format);

				// Free the allocated memory
				free(lpchTextW);

				return result; // Return the result from DrawTextW
			}
		}
	}

	// Fallback to original DrawTextA if conversion fails
	return TrueDrawTextA(hdc, lpchText, cchText, lprc, format);
}

typedef BOOL(WINAPI* OutTextA_t)(HDC hdc, LPCSTR lpString);

OutTextA_t TrueOutTextA = NULL;

BOOL WINAPI HookedOutTextA(HDC hdc, LPCSTR lpString) {
	// Custom logic before calling the original function
	if (lpString) {
		OutputDebugStringA("OutTextA Hooked!"); // Log for debugging
		lpString = "Hooked Text"; // Example: Replace the original text
	}
	return TrueOutTextA(hdc, lpString); // Call the original function
}*/
/*
// Define the prototypes for the original `send` and `recv` functions
typedef int(WINAPI* send_t)(SOCKET s, const char* buf, int len, int flags);
typedef int(WINAPI* recv_t)(SOCKET s, char* buf, int len, int flags);

// Pointers to the original functions
send_t TrueSend = NULL;
recv_t TrueRecv = NULL;

// Hooked `send` function
int WINAPI HookedSend(SOCKET s, const char* buf, int len, int flags) {
	// Call the original function
	int ret = TrueSend(s, buf, len, flags);

	if (ret > 0) {
		// Log the contents of the buffer as a hex dump
		std::ostringstream oss;
		oss << "send Hooked - Data Length: " << ret << "\n";
		//oss << "Sent Data (Hex Dump):\n";

		for (int i = 0; i < ret; ++i) {
			oss << std::hex << std::setw(2) << std::setfill('0')<< static_cast<unsigned int>(static_cast<unsigned char>(buf[i])) << " ";

			// Add a newline every 16 bytes for readability
			if ((i + 1) % 16 == 0) {
				oss << "\n";
			}
		}

		oss << "\nSent Data (ASCII):\n";
		for (int i = 0; i < ret; ++i) {
			char ch = buf[i];
			oss << (std::isprint(static_cast<unsigned char>(ch)) ? ch : '.');
		}
		oss << "\n";

		OutputDebugStringA(oss.str().c_str());
	}
	else if (ret == 0) {
		OutputDebugStringA("send Hooked - No data sent.\n");
	}
	else {
		OutputDebugStringA("send Hooked - Error occurred.\n");
	}

	return ret;
}*/
/*
// Hooked `recv` function
int WINAPI HookedRecv(SOCKET s, char* buf, int len, int flags) {
	// Call the original function to receive data
	int ret = TrueRecv(s, buf, len, flags);

	// Check if the function succeeded
	if (ret > 0) {
		// Log the contents of the buffer as a hex dump
		std::ostringstream oss;
		oss << "recv Hooked - Data Length: " << ret << "\n";
		//oss << "Recv Data (Hex Dump):\n";

		for (int i = 0; i < ret; ++i) {
			oss << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned int>(static_cast<unsigned char>(buf[i])) << " ";

			// Add a newline every 16 bytes for readability
			if ((i + 1) % 16 == 0) {
				oss << "\n";
			}
		}

		oss << "\nRecv Data (ASCII):\n";
		for (int i = 0; i < ret; ++i) {
			char ch = buf[i];
			// Replace non-printable characters with a dot
			oss << (std::isprint(static_cast<unsigned char>(ch)) ? ch : '.');
		}
		oss << "\n";

		OutputDebugStringA(oss.str().c_str());
	}
	else if (ret == 0) {
		OutputDebugStringA("recv Hooked - Connection gracefully closed.\n");
	}
	else {
		OutputDebugStringA("recv Hooked - Error occurred.\n");
	}

	// Log the call stack
	void* stack[1024]; // Buffer for stack addresses
	unsigned short frames;
	SYMBOL_INFO* symbol;
	HANDLE process = GetCurrentProcess();
	FILE* logFile = fopen("callstack_log.txt", "a");

	if (!logFile) {
		return ret;
	}

	// Initialize symbols for the current process
	SymInitialize(process, NULL, TRUE);

	// Capture the stack backtrace
	frames = CaptureStackBackTrace(0, 1024, stack, NULL);

	// Allocate memory for symbol information
	symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256 * sizeof(char), 1);
	symbol->MaxNameLen = 255;
	symbol->SizeOfStruct = sizeof(SYMBOL_INFO);

	// Log each frame
	fprintf(logFile, "Call Stack:\n");
	for (unsigned short i = 0; i < frames; i++) {
		if (SymFromAddr(process, (DWORD64)(stack[i]), 0, symbol)) {
			fprintf(logFile, "%u: %s - 0x%0llX\n", i, symbol->Name, symbol->Address);
		}
		else {
			fprintf(logFile, "%u: [Unknown function] - 0x%0llX\n", i, (DWORD64)(stack[i]));
		}
	}
	fprintf(logFile, "\n");

	// Cleanup
	free(symbol);
	SymCleanup(process);
	fclose(logFile);

	return ret;
}
*/
BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {

    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:

        DisableThreadLibraryCalls(hModule);
		//DetourRestoreAfterWith();
		//DisableThreadLibraryCalls(hModule);
		DetourTransactionBegin();
		DetourUpdateThread(GetCurrentThread());
		//InstallHook("user32.dll", "MessageBoxA", (LPVOID*)&TrueMessageBoxA, HookedMessageBoxA);
		//InstallHook("user32.dll", "DrawTextA", (LPVOID*)&TrueDrawTextA, HookedDrawTextA);
		//InstallHook("gdi32.dll", "TextOutA", (LPVOID*)&TrueOutTextA, HookedOutTextA);
		// Install hooks for `send` and `recv`
		//InstallHook("ws2_32.dll", "send", (LPVOID*)&TrueSend, HookedSend);
		//InstallHook("ws2_32.dll", "recv", (LPVOID*)&TrueRecv, HookedRecv);
		InstallHook("kernel32.dll", "MultiByteToWideChar", (LPVOID*)&TrueMultiByteToWideChar, HookedMultiByteToWideChar); //For chinese code support
		InstallHook("kernel32.dll", "WideCharToMultiByte", (LPVOID*)&TrueWideCharToMultiByte, HookedWideCharToMultiByte); //For chinese code support
		InstallHook("imm32.dll", "ImmAssociateContext", (LPVOID*)&TrueImmAssociateContext, HookedImmAssociateContext); // For stopping change of input system while game running
		//InstallHook("imm32.dll", "ImmAssociateContextEx", (LPVOID*)&TrueImmAssociateContextEx, HookedImmAssociateContextEx);
		DetourTransactionCommit();
		//StartLogging();
		Load(NULL);
		//CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)Load, hModule, NULL, NULL);
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
