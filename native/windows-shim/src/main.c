#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

#include "quote.h"

#define METADATA_MAGIC "CLDXL001"
#define METADATA_SCHEMA 1u
#define SHIM_COMPATIBILITY 1u
#define MAX_PATH_CHARS 4096u
#define MAX_METADATA_BYTES 32768u

#pragma pack(push, 1)
typedef struct LauncherHeader {
  char magic[8];
  uint32_t schema_version;
  uint32_t manager_shim_compatibility_version;
  uint32_t node_chars;
  uint32_t manager_chars;
  unsigned char installation_id[16];
  unsigned char hmac[32];
} LauncherHeader;
#pragma pack(pop)

static volatile DWORD child_group = 0;

static BOOL WINAPI relay_console(DWORD event_type) {
  if (!child_group) return FALSE;
  if (event_type == CTRL_C_EVENT || event_type == CTRL_BREAK_EVENT || event_type == CTRL_CLOSE_EVENT
    || event_type == CTRL_LOGOFF_EVENT || event_type == CTRL_SHUTDOWN_EVENT) {
    GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, child_group);
    return TRUE;
  }
  return FALSE;
}

static int same_bytes(const unsigned char *left, const unsigned char *right, size_t count) {
  unsigned char difference = 0;
  size_t index;
  for (index = 0; index < count; ++index) difference |= left[index] ^ right[index];
  return difference == 0;
}

static int safe_absolute_path(const wchar_t *value) {
  size_t length, index;
  wchar_t canonical[MAX_PATH_CHARS + 1];
  DWORD canonical_length;
  if (!value) return 0;
  length = wcslen(value);
  if (length < 4 || length > MAX_PATH_CHARS || value[1] != L':' || value[2] != L'\\') return 0;
  for (index = 0; index < length; ++index) if (value[index] == L'\r' || value[index] == L'\n') return 0;
  canonical_length = GetFullPathNameW(value, MAX_PATH_CHARS + 1, canonical, NULL);
  return canonical_length == length && canonical_length <= MAX_PATH_CHARS && _wcsicmp(canonical, value) == 0;
}

static int pin_executable_leaf(const wchar_t *target, HANDLE *pinned) {
  HANDLE file;
  FILE_ATTRIBUTE_TAG_INFO tag;
  file = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (!pinned || file == INVALID_HANDLE_VALUE) return 0;
  if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag))
    || (tag.FileAttributes & (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DIRECTORY)) != 0) {
    CloseHandle(file); return 0;
  }
  *pinned = file; return 1;
}

static int fixed_sibling(const wchar_t *directory, const wchar_t *name, wchar_t *output, size_t capacity) {
  return _snwprintf_s(output, capacity, _TRUNCATE, L"%ls\\%ls", directory, name) > 0;
}

static int read_no_reparse(const wchar_t *target, unsigned char **bytes, DWORD *length, DWORD exact_length) {
  HANDLE file = INVALID_HANDLE_VALUE;
  FILE_ATTRIBUTE_TAG_INFO tag;
  LARGE_INTEGER size;
  DWORD read = 0;
  unsigned char *buffer = NULL;
  file = CreateFileW(target, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT, NULL);
  if (file == INVALID_HANDLE_VALUE) goto fail;
  if (!GetFileInformationByHandleEx(file, FileAttributeTagInfo, &tag, sizeof(tag))
    || (tag.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    || !GetFileSizeEx(file, &size) || size.QuadPart <= 0 || size.QuadPart > MAX_METADATA_BYTES
    || (exact_length && size.QuadPart != exact_length)) goto fail;
  buffer = (unsigned char *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, (SIZE_T)size.QuadPart);
  if (!buffer || !ReadFile(file, buffer, (DWORD)size.QuadPart, &read, NULL) || read != (DWORD)size.QuadPart) goto fail;
  CloseHandle(file); *bytes = buffer; *length = read; return 1;
fail:
  if (file != INVALID_HANDLE_VALUE) CloseHandle(file);
  if (buffer) HeapFree(GetProcessHeap(), 0, buffer);
  return 0;
}

static int verify_hmac(const unsigned char *key, const LauncherHeader *header,
  const unsigned char *strings, DWORD strings_length) {
  BCRYPT_ALG_HANDLE algorithm = NULL;
  BCRYPT_HASH_HANDLE hash = NULL;
  unsigned char digest[32];
  NTSTATUS status;
  size_t prefix = offsetof(LauncherHeader, hmac);
  status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
  if (status < 0) goto fail;
  status = BCryptCreateHash(algorithm, &hash, NULL, 0, (PUCHAR)key, 32, 0);
  if (status < 0 || BCryptHashData(hash, (PUCHAR)header, (ULONG)prefix, 0) < 0
    || BCryptHashData(hash, (PUCHAR)strings, strings_length, 0) < 0
    || BCryptFinishHash(hash, digest, sizeof(digest), 0) < 0) goto fail;
  BCryptDestroyHash(hash); BCryptCloseAlgorithmProvider(algorithm, 0);
  return same_bytes(digest, header->hmac, sizeof(digest));
fail:
  if (hash) BCryptDestroyHash(hash);
  if (algorithm) BCryptCloseAlgorithmProvider(algorithm, 0);
  return 0;
}

static int append_argument(wchar_t *command_line, size_t capacity, size_t *position, const wchar_t *argument) {
  wchar_t quoted[65536];
  size_t written = 0;
  if (*position && *position + 1 < capacity) command_line[(*position)++] = L' ';
  if (!claudex_quote_argument(argument, quoted, sizeof(quoted) / sizeof(quoted[0]), &written)
    || *position + written + 1 > capacity) return 0;
  memcpy(command_line + *position, quoted, (written + 1) * sizeof(wchar_t));
  *position += written;
  return 1;
}

static int profile_for_basename(const wchar_t *basename) {
  if (_wcsicmp(basename, L"claudexctl.exe") == 0) return 0;
  if (_wcsicmp(basename, L"claudex.exe") == 0) return 1;
  if (_wcsicmp(basename, L"claude-agy.exe") == 0) return 2;
  return -1;
}

int wmain(int argc, wchar_t **argv) {
  wchar_t module[MAX_PATH_CHARS + 1], directory[MAX_PATH_CHARS + 1], metadata_path[MAX_PATH_CHARS + 32];
  wchar_t key_path[MAX_PATH_CHARS + 32], *separator, *basename, *node = NULL, *manager = NULL;
  unsigned char *metadata = NULL, *key = NULL;
  DWORD metadata_length = 0, key_length = 0, exit_code = 7;
  LauncherHeader *header;
  unsigned char *strings;
  DWORD strings_length;
  size_t expected_bytes, position = 0;
  wchar_t command_line[32768];
  STARTUPINFOW startup;
  PROCESS_INFORMATION process;
  HANDLE node_file = INVALID_HANDLE_VALUE, manager_file = INVALID_HANDLE_VALUE;
  int profile, index;
  if (!GetModuleFileNameW(NULL, module, MAX_PATH_CHARS) || wcslen(module) >= MAX_PATH_CHARS) goto cleanup;
  wcscpy_s(directory, MAX_PATH_CHARS + 1, module);
  separator = wcsrchr(directory, L'\\');
  if (!separator) goto cleanup;
  basename = separator + 1; *separator = L'\0';
  profile = profile_for_basename(basename);
  if (profile < 0 || !fixed_sibling(directory, L"claudex-launcher.bin", metadata_path, MAX_PATH_CHARS + 32)
    || !fixed_sibling(directory, L"claudex-launcher.key", key_path, MAX_PATH_CHARS + 32)
    || !read_no_reparse(metadata_path, &metadata, &metadata_length, 0)
    || !read_no_reparse(key_path, &key, &key_length, 32)
    || metadata_length < sizeof(LauncherHeader)) goto cleanup;
  header = (LauncherHeader *)metadata;
  if (memcmp(header->magic, METADATA_MAGIC, 8) != 0 || header->schema_version != METADATA_SCHEMA
    || header->manager_shim_compatibility_version != SHIM_COMPATIBILITY
    || header->node_chars < 4 || header->node_chars > MAX_PATH_CHARS
    || header->manager_chars < 4 || header->manager_chars > MAX_PATH_CHARS) goto cleanup;
  strings = metadata + sizeof(LauncherHeader);
  strings_length = metadata_length - (DWORD)sizeof(LauncherHeader);
  expected_bytes = ((size_t)header->node_chars + (size_t)header->manager_chars) * sizeof(wchar_t);
  if (expected_bytes != strings_length || !verify_hmac(key, header, strings, strings_length)) goto cleanup;
  node = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((SIZE_T)header->node_chars + 1) * sizeof(wchar_t));
  manager = (wchar_t *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, ((SIZE_T)header->manager_chars + 1) * sizeof(wchar_t));
  if (!node || !manager) goto cleanup;
  memcpy(node, strings, header->node_chars * sizeof(wchar_t));
  memcpy(manager, strings + header->node_chars * sizeof(wchar_t), header->manager_chars * sizeof(wchar_t));
  if (wcslen(node) != header->node_chars || wcslen(manager) != header->manager_chars
    || !safe_absolute_path(node) || !safe_absolute_path(manager)
    || !pin_executable_leaf(node, &node_file) || !pin_executable_leaf(manager, &manager_file)) goto cleanup;
  command_line[0] = L'\0';
  if (!append_argument(command_line, 32768, &position, node)
    || !append_argument(command_line, 32768, &position, manager)) goto cleanup;
  if (profile == 1 && (!append_argument(command_line, 32768, &position, L"launcher")
    || !append_argument(command_line, 32768, &position, L"claudex"))) goto cleanup;
  if (profile == 2 && (!append_argument(command_line, 32768, &position, L"launcher")
    || !append_argument(command_line, 32768, &position, L"claude-agy"))) goto cleanup;
  for (index = 1; index < argc; ++index) if (!append_argument(command_line, 32768, &position, argv[index])) goto cleanup;
  ZeroMemory(&startup, sizeof(startup)); ZeroMemory(&process, sizeof(process));
  startup.cb = sizeof(startup); startup.dwFlags = STARTF_USESTDHANDLES;
  startup.hStdInput = GetStdHandle(STD_INPUT_HANDLE); startup.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  startup.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  if (!CreateProcessW(node, command_line, NULL, NULL, TRUE, CREATE_UNICODE_ENVIRONMENT | CREATE_NEW_PROCESS_GROUP,
    NULL, NULL, &startup, &process)) goto cleanup;
  child_group = process.dwProcessId; SetConsoleCtrlHandler(relay_console, TRUE);
  CloseHandle(process.hThread);
  if (WaitForSingleObject(process.hProcess, INFINITE) != WAIT_OBJECT_0 || !GetExitCodeProcess(process.hProcess, &exit_code)) exit_code = 7;
  CloseHandle(process.hProcess); child_group = 0; SetConsoleCtrlHandler(relay_console, FALSE);
cleanup:
  if (node_file != INVALID_HANDLE_VALUE) CloseHandle(node_file);
  if (manager_file != INVALID_HANDLE_VALUE) CloseHandle(manager_file);
  if (metadata) { SecureZeroMemory(metadata, metadata_length); HeapFree(GetProcessHeap(), 0, metadata); }
  if (key) { SecureZeroMemory(key, key_length); HeapFree(GetProcessHeap(), 0, key); }
  if (node) { SecureZeroMemory(node, (wcslen(node) + 1) * sizeof(wchar_t)); HeapFree(GetProcessHeap(), 0, node); }
  if (manager) { SecureZeroMemory(manager, (wcslen(manager) + 1) * sizeof(wchar_t)); HeapFree(GetProcessHeap(), 0, manager); }
  return (int)exit_code;
}
