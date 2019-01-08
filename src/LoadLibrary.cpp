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
	/* Microsoft Windows (64-bit) */
	PIMAGE_NT_HEADERS64 NT_HEADERS = (PIMAGE_NT_HEADERS64)&buffer[DOS_HEADER->e_lfanew];
#elif defined(_WIN32)
	PIMAGE_NT_HEADERS32 NT_HEADERS = (PIMAGE_NT_HEADERS32)&buffer[DOS_HEADER->e_lfanew];
	/* Microsoft Windows (32-bit) */
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
  //_mysection mysection = new _mysection[NT_HEADERS->FileHeader.NumberOfSections];

  mysection *section_array = (mysection*)VirtualAlloc(NULL, NT_HEADERS->FileHeader.NumberOfSections*sizeof(mysection), MEM_COMMIT, PAGE_READWRITE);
  if(section_array == NULL) {
#ifdef DEBUG
  		std::cerr << "unable to allocate" << std::endl;
#endif
      return NULL;
  }
  bool allocated = TRUE;
  for(uint32_t secnb=0; secnb<NT_HEADERS->FileHeader.NumberOfSections; secnb++) {
      PIMAGE_SECTION_HEADER section = (PIMAGE_SECTION_HEADER)&buffer[headerlen + sizeof(IMAGE_SECTION_HEADER) * secnb];
#ifdef DEBUG
      std::cout << "New section found: "  << section->Name << std::endl;
#endif
      section_array[secnb].address = (void *)VirtualAlloc(NULL, section->Misc.VirtualSize, MEM_COMMIT, section->Characteristics);
      if(section_array[secnb].address == NULL) {
        allocated = FALSE;
      }
  }
  if(!allocated) {
#ifdef DEBUG
    std::cerr << "unable to allocate all sections" << std::endl;
#endif
    for(uint32_t secnb=0; secnb<NT_HEADERS->FileHeader.NumberOfSections; secnb++) {
      if(section_array[secnb].address != NULL) {
        VirtualFree(section_array[secnb].address, 0, MEM_RELEASE);
      }
    }
    VirtualFree(section_array, 0, MEM_RELEASE);
    return 0;
  }
  VirtualFree(section_array, 0, MEM_RELEASE);
#ifdef DEBUG
    std::cerr << "SUCCESS" << std::endl;
#endif
	return NULL;
}


#ifdef DEBUG
int main(int argc, char **argv)
{
	if(argc != 2) {
		std::cerr << "usage: " << argv[0] << " <file.dll>" << std::endl;
		return -1;
	}
	std::ifstream infile(argv[1], std::ios::binary);
	if(infile.is_open()) {
		infile.seekg (0, infile.end);
		size_t length = infile.tellg();
		infile.seekg (0, infile.beg);
		char *buffer = new char[length];
		infile.read(buffer, length);
		LoadLibraryFomMem(buffer, length);
		delete[] buffer;
	}
	infile.close();
	return 0;
}
#endif
