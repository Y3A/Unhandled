#ifndef POC_H
#define POC_H

#define SystemHandleInformation 0x10

typedef struct _SYSTEM_HANDLE
{
    DWORD       dwProcessId;
    BYTE        bObjectType;
    BYTE        bFLags;
    WORD        wValue;
    PVOID       pAddress;
    ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, *PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
    DWORD           NumberOfHandles;
    SYSTEM_HANDLE   Handles[1];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (NTAPI *NQSI) (
    IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL
);

typedef struct _PID_HANDLE_OBJECT_MAP
{
    DWORD                         pid;
    HANDLE                        handle;
    void                          *object;
    struct _PID_HANDLE_OBJECT_MAP *next;
} PID_HANDLE_OBJECT_MAP, *PPID_HANDLE_OBJECT_MAP;

typedef struct _TARGET
{
    DWORD           pid;
    HANDLE          handle;
    ACCESS_MASK     access_type;
    DWORD           integrity;
    struct _TARGET  *next;
} TARGET, *PTARGET;

NTSTATUS resolve_symbols(void);
NTSTATUS init_map(void);
NTSTATUS query_handles(_Out_ PSYSTEM_HANDLE_INFORMATION *handles);
NTSTATUS fill_map(_In_ PSYSTEM_HANDLE_INFORMATION handles);
NTSTATUS search_targets(_In_ PSYSTEM_HANDLE_INFORMATION handles);
NTSTATUS get_integrity(_In_ DWORD pid, _Out_ PDWORD integrity_level);

NTSTATUS spoof_parent(_In_ DWORD pid, _In_ HANDLE handle);
NTSTATUS create_thread(_In_ DWORD pid, _In_ HANDLE handle);

NTSTATUS get_base_address(_In_ DWORD pid, _In_ const wchar_t *name, _Out_ UINT64 *base);

#endif