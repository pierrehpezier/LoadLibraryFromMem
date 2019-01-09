# LoadLibraryFromMem
Shellcode LoadLibrary from buf


# Functions exported
```
/*!
 * \brief
 * Loads a dll from an url and execute export by name
 * \param [in] url
 * The url of the dll
 * \param [in] functioname
 * The export name
 */
bool DownloadExecDll(char *url, char *functioname)
```

```
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
```

```
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
```

# TODO

makes 32bits version works
