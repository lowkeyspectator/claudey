#ifndef CLAUDEX_QUOTE_H
#define CLAUDEX_QUOTE_H

#include <stddef.h>
#include <wchar.h>

int claudex_quote_argument(const wchar_t *argument, wchar_t *output, size_t capacity, size_t *written);

#endif
