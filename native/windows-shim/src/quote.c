#include "quote.h"

#include <wctype.h>

static int append(wchar_t value, wchar_t *output, size_t capacity, size_t *position) {
  if (*position + 1 >= capacity) return 0;
  output[(*position)++] = value;
  return 1;
}

static int append_slashes(size_t count, wchar_t *output, size_t capacity, size_t *position) {
  while (count-- > 0) if (!append(L'\\', output, capacity, position)) return 0;
  return 1;
}

int claudex_quote_argument(const wchar_t *argument, wchar_t *output, size_t capacity, size_t *written) {
  size_t index = 0, position = 0, backslashes = 0;
  int needs_quotes = 0;
  if (!argument || !output || !written || capacity == 0) return 0;
  if (argument[0] == L'\0') needs_quotes = 1;
  for (index = 0; argument[index] != L'\0'; ++index) {
    if (argument[index] == L'"' || iswspace(argument[index])) needs_quotes = 1;
  }
  if (!needs_quotes) {
    for (index = 0; argument[index] != L'\0'; ++index) if (!append(argument[index], output, capacity, &position)) return 0;
    output[position] = L'\0'; *written = position; return 1;
  }
  if (!append(L'"', output, capacity, &position)) return 0;
  for (index = 0; argument[index] != L'\0'; ++index) {
    if (argument[index] == L'\\') { ++backslashes; continue; }
    if (argument[index] == L'"') {
      /* Microsoft argv rule: emit 2 * backslashes + 1 before a literal quote. */
      if (!append_slashes(2 * backslashes + 1, output, capacity, &position)
        || !append(L'"', output, capacity, &position)) return 0;
    } else {
      if (!append_slashes(backslashes, output, capacity, &position)
        || !append(argument[index], output, capacity, &position)) return 0;
    }
    backslashes = 0;
  }
  if (!append_slashes(2 * backslashes, output, capacity, &position)
    || !append(L'"', output, capacity, &position)) return 0;
  output[position] = L'\0'; *written = position; return 1;
}
