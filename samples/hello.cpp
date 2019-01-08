#include <windows.h>

extern "C" {
	void __declspec(dllexport) hello(void)
	{
		MessageBoxA(0, "hello from DLL", "hello", 0);
	}
}

