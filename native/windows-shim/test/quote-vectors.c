#include <stdio.h>
#include <wchar.h>

#include "quote.h"

typedef struct Vector { const wchar_t *input; const wchar_t *expected; } Vector;

int main(void) {
  wchar_t output[1024];
  size_t written = 0, index;
  const Vector vectors[] = {
    { L"", L"\"\"" }, { L"plain", L"plain" }, { L"two words", L"\"two words\"" },
    { L"\u96ea", L"\u96ea" }, { L"\"", L"\"\\\"\"" }, { L"a\"b", L"\"a\\\"b\"" },
    { L"a\\\"b", L"\"a\\\\\\\"b\"" }, { L"ends\\", L"ends\\" },
    { L"ends slash \\", L"\"ends slash \\\\\"" }, { L"--leading", L"--leading" },
    { L";&|`$()%VAR%", L";&|`$()%VAR%" }, { L"line\r\nbreak", L"\"line\r\nbreak\"" }
  };
  for (index = 0; index < sizeof(vectors) / sizeof(vectors[0]); ++index) {
    if (!claudex_quote_argument(vectors[index].input, output, sizeof(output) / sizeof(output[0]), &written)
      || wcscmp(output, vectors[index].expected) != 0 || written != wcslen(output)) {
      fwprintf(stderr, L"vector %zu failed\n", index); return 1;
    }
  }
  return 0;
}
