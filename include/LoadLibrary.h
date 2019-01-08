#include <windows.h>

#ifdef _DEBUG
#define DEBUG	//Visual studio workaround
#endif
#ifdef DEBUG
#include <iostream>
#include <fstream>
#include <iostream>
#endif

#if defined(_WIN64)
#define PMYIMAGE_THUNK_DATA	PIMAGE_THUNK_DATA64
#elif defined(_WIN32)
#define PMYIMAGE_THUNK_DATA	PIMAGE_THUNK_DATA32
#endif

