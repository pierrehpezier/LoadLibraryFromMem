#include "include/LoadLibrary.h"


HMODULE LoadLibraryFomMem(char *buffer, size_t length)
{
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
  		std::cerr << "file truncated" << std::endl;
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
  }
  void *ImageBase = (void *)VirtualAlloc(NULL, high, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
	  if (importdescriptor->Name == NULL)
		  break;
	  for (DWORD funcnb = 0;; funcnb++) {
		  PMYIMAGE_THUNK_DATA thunk1 = PMYIMAGE_THUNK_DATA((char *)ImageBase + importdescriptor->OriginalFirstThunk + funcnb * sizeof(PMYIMAGE_THUNK_DATA));
		  PMYIMAGE_THUNK_DATA thunk2 = PMYIMAGE_THUNK_DATA((char *)ImageBase + importdescriptor->FirstThunk + funcnb * sizeof(PMYIMAGE_THUNK_DATA));
		  if (thunk1->u1.ForwarderString == NULL || thunk2->u1.AddressOfData == NULL) {
			  break;
		  }
		  thunk2->u1.AddressOfData = (ULONGLONG)GetProcAddress(LoadLibraryA((char *)ImageBase + importdescriptor->Name), (char *)ImageBase + thunk1->u1.ForwarderString + 2);
		  if (thunk2->u1.AddressOfData == NULL) {
#ifdef DEBUG
			  std::cerr << "failed to load" << (char *)ImageBase + importdescriptor->Name << ":" << (char *)ImageBase + thunk1->u1.ForwarderString + 2 << std::endl;
#endif
			  return NULL;
		  }
	  }
  }
  //parse relocation
  /*
  IMAGE_RELOCATION relocation = IMAGE_RELOCATION((char *)ImageBase + NT_HEADERS->OptionalHeader.DataDirectory[6].VirtualAddress + sizeof(IMAGE_IMPORT_DESCRIPTOR)*dllnb);
  */
  //Restore the rights
  for (DWORD secnb = 0; secnb<NT_HEADERS->FileHeader.NumberOfSections; secnb++) {
	  PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)&buffer[headerlen + sizeof(IMAGE_SECTION_HEADER) * secnb];
	  DWORD myoldprotect = 0;
	  VirtualProtect(&((char *)ImageBase)[section->VirtualAddress], section->Misc.VirtualSize, section->Characteristics, &myoldprotect);
  }
#ifdef DEBUG
    std::cerr << "SUCCESS" << std::endl;
#endif
	return (HMODULE)ImageBase;
}


#ifdef DEBUG
int main(int argc, char **argv)
{
	std::ifstream infile("build/hello64.dll", std::ios::binary);
	HMODULE mylib = NULL;
	if(infile.is_open()) {
		infile.seekg (0, infile.end);
		size_t length = infile.tellg();
		infile.seekg (0, infile.beg);
		char *buffer = new char[length];
		infile.read(buffer, length);
		mylib = LoadLibraryFomMem(buffer, length);
		delete[] buffer;
	}
	infile.close();
	typedef void (WINAPI *_hello)(void);
	_hello hello = (_hello)((char *)mylib + 0x1450);
	hello();
	return 0;
}
#endif
