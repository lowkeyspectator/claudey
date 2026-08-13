#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <wchar.h>

int wmain(int argc, wchar_t **argv) {
  int index, character;
  wprintf(L"%d\n", argc);
  for (index = 0; index < argc; ++index) {
    size_t length = wcslen(argv[index]);
    wprintf(L"%zu:", length);
    for (character = 0; character < (int)length; ++character) wprintf(L"%04x", (unsigned int)argv[index][character]);
    wprintf(L"\n");
  }
  fflush(stdout);
  return 23;
}
