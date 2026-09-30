/* Machine-scoped Interactive User registry selection and admission.
 * Copyright 2026 LinuxNT contributors
 * LGPL-2.1-or-later
 */
#define COBJMACROS
#include <stdio.h>
#include "windows.h"
#include "winternl.h"
#include "objbase.h"
#include "sddl.h"
#include "irpcss.h"
#include "initguid.h"
#include "stdactivator.h"
#include "wine/test.h"
#include "wine/exception.h"

#define COM_PUBLISHER 0x80000000u
static const CLSID activator_clsid = {0x0000033c, 0, 0, {0xc0, 0, 0, 0, 0, 0, 0, 0x46}};
static DWORD publisher_value;
static HRESULT WINAPI factory_query(IClassFactory *iface, REFIID iid, void **object)
{
    *object = NULL;
    if (!IsEqualIID(iid, &IID_IUnknown) && !IsEqualIID(iid, &IID_IClassFactory)) return E_NOINTERFACE;
    *object = iface;
    IClassFactory_AddRef(iface);
    return S_OK;
}
static ULONG WINAPI factory_addref(IClassFactory *iface) { return 2; }
static ULONG WINAPI factory_release(IClassFactory *iface) { return 1; }
static HRESULT WINAPI factory_create(IClassFactory *iface, IUnknown *outer, REFIID iid, void **object)
{
    IStream *stream;
    LARGE_INTEGER zero = {{0}};
    ULONG written;
    HRESULT hr;
    *object = NULL;
    if (outer) return CLASS_E_NOAGGREGATION;
    hr = CreateStreamOnHGlobal(NULL, TRUE, &stream);
    if (FAILED(hr)) return hr;
    hr = IStream_Write(stream, &publisher_value, sizeof(publisher_value), &written);
    if (SUCCEEDED(hr)) hr = IStream_Seek(stream, zero, STREAM_SEEK_SET, NULL);
    if (SUCCEEDED(hr)) hr = IStream_QueryInterface(stream, iid, object);
    IStream_Release(stream);
    return hr;
}
static HRESULT WINAPI factory_lock(IClassFactory *iface, BOOL lock) { return S_OK; }
static const IClassFactoryVtbl factory_vtbl =
{
    factory_query, factory_addref, factory_release, factory_create, factory_lock
};
static IClassFactory factory = {&factory_vtbl};

static RPC_BINDING_HANDLE binding;
static GUID clsid;
static HKEY appid_key, machine_key;
static const SID system_sid = {SID_REVISION, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_LOCAL_SYSTEM_RID}};
static const SID interactive_sid = {SID_REVISION, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_INTERACTIVE_RID}};
static const SID world_sid = {SID_REVISION, 1, {SECURITY_WORLD_SID_AUTHORITY}, {SECURITY_WORLD_RID}};
static const SID authenticated_sid = {SID_REVISION, 1, {SECURITY_NT_AUTHORITY}, {SECURITY_AUTHENTICATED_USER_RID}};

struct saved_value { BYTE *data; DWORD size, type; BOOL present; };

static BOOL bind_rpcss(void)
{
    RPC_WSTR string;
    RPC_STATUS status;
    status = RpcStringBindingComposeW(NULL, (RPC_WSTR)L"ncalrpc", NULL, (RPC_WSTR)L"irpcss", NULL, &string);
    ok(!status, "Compose binding returned %lu.\n", status);
    if (status) return FALSE;
    status = RpcBindingFromStringBindingW(string, &binding);
    RpcStringFreeW(&string);
    ok(!status, "Create binding returned %lu.\n", status);
    return !status;
}

static BOOL start_rpcss(void)
{
    STARTUPINFOA startup = {sizeof(startup)};
    PROCESS_INFORMATION process;
    char command[] = "rpcss.exe --standalone";
    DWORD deadline = GetTickCount() + 10000, sequence;
    RPC_STATUS status;
    BOOL launched = FALSE;
    do
    {
        status = RPC_S_OK;
        RpcTryExcept { irpcss_get_thread_seq_id(binding, &sequence); }
        RpcExcept(1) { status = RpcExceptionCode(); }
        RpcEndExcept
        if (!status) return TRUE;
        if (!launched)
        {
            launched = CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process);
            ok(launched, "Start RPCSS failed: %lu.\n", GetLastError());
            if (!launched) return FALSE;
            CloseHandle(process.hThread);
            CloseHandle(process.hProcess);
        }
        Sleep(50);
    } while ((LONG)(deadline - GetTickCount()) > 0);
    ok(0, "RPCSS endpoint unavailable: %lu.\n", status);
    return FALSE;
}

static HANDLE user_token(PSID sid, DWORD session, BOOL interactive)
{
    BYTE acl_buffer[256];
    ACL *acl = (ACL *)acl_buffer;
    TOKEN_USER user = {{sid, 0}};
    TOKEN_OWNER owner = {sid};
    TOKEN_PRIMARY_GROUP group = {sid};
    struct { DWORD count; SID_AND_ATTRIBUTES groups[3]; } groups = {2, {
        {(PSID)&world_sid, SE_GROUP_ENABLED | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT},
        {(PSID)&authenticated_sid, SE_GROUP_ENABLED | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT},
        {(PSID)&interactive_sid, SE_GROUP_ENABLED | SE_GROUP_MANDATORY | SE_GROUP_ENABLED_BY_DEFAULT}}};
    TOKEN_PRIVILEGES privileges = {0};
    TOKEN_DEFAULT_DACL default_dacl = {acl};
    TOKEN_SOURCE source = {{'R','P','C','S','S'}};
    OBJECT_ATTRIBUTES attributes;
    LARGE_INTEGER expiration;
    LUID authentication;
    HANDLE token = NULL;
    NTSTATUS status;

    if (interactive) groups.count = 3;
    InitializeAcl(acl, sizeof(acl_buffer), ACL_REVISION);
    AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, sid);
    AddAccessAllowedAce(acl, ACL_REVISION, GENERIC_ALL, (PSID)&system_sid);
    InitializeObjectAttributes(&attributes, NULL, 0, NULL, NULL);
    NtAllocateLocallyUniqueId(&authentication);
    NtAllocateLocallyUniqueId(&source.SourceIdentifier);
    expiration.QuadPart = MAXLONGLONG;
    status = NtCreateToken(&token, TOKEN_ALL_ACCESS, &attributes, TokenPrimary, &authentication,
                          &expiration, &user, (TOKEN_GROUPS *)&groups, &privileges, &owner,
                          &group, &default_dacl, &source);
    ok(!status, "Create user token returned %#lx.\n", status);
    if (status) return NULL;
    ok(SetTokenInformation(token, TokenSessionId, &session, sizeof(session)),
       "Assign user session %lu failed: %lu.\n", session, GetLastError());
    return token;
}

static void publisher(const char *guid_string, const char *pipe_string, DWORD value, DWORD flags)
{
    struct { ULONG size; DWORD value; } object = {sizeof(DWORD), value};
    WCHAR guid[40];
    GUID id;
    HANDLE pipe = (HANDLE)(ULONG_PTR)_strtoui64(pipe_string, NULL, 16);
    unsigned int cookie = 0;
    DWORD written;
    HRESULT hr;

    MultiByteToWideChar(CP_ACP, 0, guid_string, -1, guid, ARRAY_SIZE(guid));
    if (FAILED(CLSIDFromString(guid, &id)) || !bind_rpcss()) ExitProcess(2);
    if (flags & COM_PUBLISHER)
    {
        DWORD com_cookie = 0;
        publisher_value = value;
        hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
        if (FAILED(hr)) ExitProcess(5);
        hr = CoRegisterClassObject(&id, (IUnknown *)&factory, CLSCTX_LOCAL_SERVER,
                                   flags & ~COM_PUBLISHER, &com_cookie);
        cookie = com_cookie;
    }
    else hr = irpcss_server_register(binding, &id, flags, (MInterfacePointer *)&object, &cookie);
    ok(hr == S_OK && cookie, "Publisher registration returned %#lx, cookie %u.\n", hr, cookie);
    if (FAILED(hr)) ExitProcess(3);
    if (!WriteFile(pipe, &cookie, sizeof(cookie), &written, NULL) || written != sizeof(cookie)) ExitProcess(4);
    CloseHandle(pipe);
    Sleep(INFINITE);
}

static BOOL start_publisher(HANDLE token, DWORD value, DWORD flags, PROCESS_INFORMATION *process)
{
    SECURITY_ATTRIBUTES attributes = {sizeof(attributes), NULL, TRUE};
    STARTUPINFOA startup = {sizeof(startup)};
    HANDLE reader, writer;
    char executable[MAX_PATH], guid[40], command[3 * MAX_PATH];
    WCHAR guidW[40];
    DWORD deadline, available = 0, count, cookie;
    BOOL ret;

    ret = CreatePipe(&reader, &writer, &attributes, 0);
    ok(ret, "Create pipe failed: %lu.\n", GetLastError());
    if (!ret) return FALSE;
    SetHandleInformation(reader, HANDLE_FLAG_INHERIT, 0);
    StringFromGUID2(&clsid, guidW, ARRAY_SIZE(guidW));
    WideCharToMultiByte(CP_ACP, 0, guidW, -1, guid, sizeof(guid), NULL, NULL);
    GetModuleFileNameA(NULL, executable, ARRAY_SIZE(executable));
    sprintf(command, "\"%s\" session publisher %s %I64x %lu %lu", executable, guid,
            (UINT64)(ULONG_PTR)writer, value, flags);
    ret = CreateProcessAsUserA(token, NULL, command, NULL, NULL, TRUE, 0, NULL, NULL, &startup, process);
    CloseHandle(writer);
    ok(ret, "Start user publisher failed: %lu.\n", GetLastError());
    if (ret)
    {
        deadline = GetTickCount() + 10000;
        do
        {
            if (!PeekNamedPipe(reader, NULL, 0, NULL, &available, NULL)) break;
            if (available >= sizeof(cookie)) break;
            if (WaitForSingleObject(process->hProcess, 0) == WAIT_OBJECT_0) break;
            Sleep(10);
        } while ((LONG)(deadline - GetTickCount()) > 0);
        ret = available >= sizeof(cookie) && ReadFile(reader, &cookie, sizeof(cookie), &count, NULL) && count == sizeof(cookie);
        ok(ret, "Publisher did not register.\n");
        if (!ret)
        {
            TerminateProcess(process->hProcess, 4);
            WaitForSingleObject(process->hProcess, 10000);
            CloseHandle(process->hThread);
            CloseHandle(process->hProcess);
            memset(process, 0, sizeof(*process));
        }
    }
    CloseHandle(reader);
    return ret;
}

static void stop_publisher(PROCESS_INFORMATION *process)
{
    if (!process->hProcess) return;
    ok(TerminateProcess(process->hProcess, 0), "Terminate publisher failed: %lu.\n", GetLastError());
    ok(WaitForSingleObject(process->hProcess, 10000) == WAIT_OBJECT_0, "Publisher did not exit.\n");
    CloseHandle(process->hThread);
    CloseHandle(process->hProcess);
    memset(process, 0, sizeof(*process));
}

static void check_class(DWORD session, DWORD context, HRESULT expected, DWORD expected_value)
{
    MInterfacePointer *object = NULL;
    DWORD value = 0;
    HRESULT hr = irpcss_get_class_object_session(binding, &clsid, session, context, &object);
    ok(hr == expected, "Session %lu context %#lx: %#lx, expected %#lx.\n", session, context, hr, expected);
    if (SUCCEEDED(expected))
    {
        ok(!!object, "Missing selected class.\n");
        if (object)
        {
            ok(object->ulCntData == sizeof(value), "Unexpected object size %lu.\n", object->ulCntData);
            if (object->ulCntData == sizeof(value)) memcpy(&value, object->abData, sizeof(value));
            ok(value == expected_value, "Selected value %lu, expected %lu.\n", value, expected_value);
        }
    }
    else ok(!object, "Rejected request returned %p.\n", object);
    if (object) MIDL_user_free(object);
}

static void set_permission(HKEY key, const WCHAR *name, const WCHAR *sddl)
{
    SECURITY_DESCRIPTOR *descriptor;
    ULONG size;
    BOOL ret = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
                                                                   (void **)&descriptor, &size);
    ok(ret, "Parse permission failed: %lu.\n", GetLastError());
    if (!ret) return;
    ok(!RegSetValueExW(key, name, 0, REG_BINARY, (BYTE *)descriptor, size), "Write permission failed.\n");
    LocalFree(descriptor);
}

static void set_null_permission(void)
{
    SECURITY_DESCRIPTOR descriptor;
    BYTE buffer[128];
    DWORD size = sizeof(buffer);
    InitializeSecurityDescriptor(&descriptor, SECURITY_DESCRIPTOR_REVISION);
    SetSecurityDescriptorOwner(&descriptor, (PSID)&system_sid, FALSE);
    SetSecurityDescriptorGroup(&descriptor, (PSID)&system_sid, FALSE);
    SetSecurityDescriptorDacl(&descriptor, TRUE, NULL, FALSE);
    ok(MakeSelfRelativeSD(&descriptor, (void *)buffer, &size), "Make null DACL policy.\n");
    ok(!RegSetValueExW(appid_key, L"LaunchPermission", 0, REG_BINARY, buffer, size), "Write null DACL policy.\n");
}

/* These callback bodies are deliberately unsupported. Only ordinary ACEs
 * may independently authorize this partition; no condition is evaluated. */
static void set_callback_permission(BOOL ordinary_grant, BOOL deny)
{
    SECURITY_DESCRIPTOR *descriptor;
    ACL *acl;
    ACE_HEADER *ace;
    ULONG size;
    BOOL present, defaulted;
    const WCHAR *sddl = ordinary_grant ? L"O:SYG:SYD:(A;;0x1f;;;SY)(A;;0x1f;;;AU)" :
                                       L"O:SYG:SYD:(A;;0x1f;;;SY)";
    ok(ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1,
                                                            (void **)&descriptor, &size), "Parse callback policy.\n");
    GetSecurityDescriptorDacl(descriptor, &present, &acl, &defaulted);
    GetAce(acl, ordinary_grant ? 1 : 0, (void **)&ace);
    ace->AceType = deny ? ACCESS_DENIED_CALLBACK_ACE_TYPE : ACCESS_ALLOWED_CALLBACK_ACE_TYPE;
    ok(!RegSetValueExW(appid_key, L"LaunchPermission", 0, REG_BINARY, (BYTE *)descriptor, size),
       "Write callback policy.\n");
    LocalFree(descriptor);
}

static void save_value(const WCHAR *name, struct saved_value *value)
{
    LSTATUS status = RegQueryValueExW(machine_key, name, NULL, &value->type, NULL, &value->size);
    ok(!status || status == ERROR_FILE_NOT_FOUND, "Read old policy returned %ld.\n", status);
    value->present = !status;
    if (!value->present) return;
    value->data = malloc(value->size ? value->size : 1);
    ok(!!value->data, "Allocate old policy.\n");
    if (value->data) ok(!RegQueryValueExW(machine_key, name, NULL, NULL, value->data, &value->size),
                       "Save old policy.\n");
}

static void restore_value(const WCHAR *name, struct saved_value *value)
{
    if (value->present && value->data)
        ok(!RegSetValueExW(machine_key, name, 0, value->type, value->data, value->size), "Restore policy.\n");
    else if (!value->present) RegDeleteValueW(machine_key, name);
    free(value->data);
}

static void check_com(IStandardActivator *activator, DWORD context, COSERVERINFO *server,
                      HRESULT expected, DWORD expected_value)
{
    IClassFactory *selected = (void *)0xdeadbeef;
    IStream *stream = NULL;
    ULONG count;
    DWORD value = 0;
    HRESULT hr = IStandardActivator_StandardGetClassObject(activator, &clsid, context, server,
                                                          &IID_IClassFactory, (void **)&selected);
    ok(hr == expected, "COM selection returned %#lx, expected %#lx.\n", hr, expected);
    if (FAILED(hr))
    {
        ok(!selected, "COM failure left output %p.\n", selected);
        return;
    }
    ok(!!selected && selected != (void *)0xdeadbeef, "Missing COM factory.\n");
    if (!selected || selected == (void *)0xdeadbeef) return;
    hr = IClassFactory_CreateInstance(selected, NULL, &IID_IStream, (void **)&stream);
    ok(hr == S_OK && stream, "Create marshaled instance returned %#lx, %p.\n", hr, stream);
    if (stream)
    {
        hr = IStream_Read(stream, &value, sizeof(value), &count);
        ok(hr == S_OK && count == sizeof(value) && value == expected_value,
           "Read selected publisher returned %#lx, %lu bytes, %lu expected %lu.\n", hr, count, value, expected_value);
        IStream_Release(stream);
    }
    IClassFactory_Release(selected);
}

static void com_client(const char *guid_string)
{
    IStandardActivator *activator;
    ISpecialSystemProperties *properties;
    WCHAR guid[40], shadow_path[128];
    HKEY shadow_key;
    DWORD session;
    BOOL console, remote;
    HRESULT hr;

    MultiByteToWideChar(CP_ACP, 0, guid_string, -1, guid, ARRAY_SIZE(guid));
    CLSIDFromString(guid, &clsid);
    swprintf(shadow_path, ARRAY_SIZE(shadow_path), L"Software\\Classes\\CLSID\\%s", guid);
    ok(!RegCreateKeyExW(HKEY_CURRENT_USER, shadow_path, 0, NULL, 0, KEY_ALL_ACCESS,
                       NULL, &shadow_key, NULL), "Create user class shadow.\n");
    ok(!RegSetValueExW(shadow_key, L"AppID", 0, REG_SZ, (BYTE *)L"invalid", sizeof(L"invalid")),
       "Write user class shadow.\n");
    RegCloseKey(shadow_key);
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "Initialize user client COM: %#lx.\n", hr);
    if (FAILED(hr)) return;
    hr = CoCreateInstance(&activator_clsid, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IStandardActivator, (void **)&activator);
    ok(hr == S_OK, "Create user activator: %#lx.\n", hr);
    if (FAILED(hr)) goto done;
    hr = IStandardActivator_QueryInterface(activator, &IID_ISpecialSystemProperties, (void **)&properties);
    ok(hr == S_OK, "Get user properties: %#lx.\n", hr);
    if (FAILED(hr)) { IStandardActivator_Release(activator); goto done; }
    ISpecialSystemProperties_SetSessionId(properties, 2, FALSE, FALSE);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, S_OK, 111);
    hr = ISpecialSystemProperties_GetSessionId2(properties, &session, &console, &remote);
    ok(hr == S_OK && session == 2 && !console && !remote, "Routing changed stored properties.\n");
    ISpecialSystemProperties_SetSessionId(properties, 2, FALSE, TRUE);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, S_OK, 222);
    ISpecialSystemProperties_SetSessionId(properties, 2, TRUE, FALSE);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, S_OK, 111);
    ISpecialSystemProperties_SetSessionId(properties, 2, TRUE, TRUE);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, E_NOTIMPL, 0);
    ISpecialSystemProperties_Release(properties);
    IStandardActivator_Release(activator);
done:
    CoUninitialize();
    RegDeleteKeyW(HKEY_CURRENT_USER, shadow_path);
}

static void test_com_selection(HANDLE first_token, HANDLE second_token)
{
    PROCESS_INFORMATION first = {0}, second = {0}, client = {0};
    IStandardActivator *activator;
    ISpecialSystemProperties *properties;
    STARTUPINFOA startup = {sizeof(startup)};
    COSERVERINFO server = {0};
    WCHAR guidW[40];
    char executable[MAX_PATH], guid[40], command[3 * MAX_PATH];
    DWORD status;
    MULTI_QI result = {&IID_IStream};
    HRESULT hr;

    if (!start_publisher(first_token, 111, COM_PUBLISHER | REGCLS_MULTIPLEUSE, &first) ||
        !start_publisher(second_token, 222, COM_PUBLISHER | REGCLS_MULTIPLEUSE, &second)) goto done;
    hr = CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ok(hr == S_OK, "Initialize client COM: %#lx.\n", hr);
    if (FAILED(hr)) goto done;
    hr = CoCreateInstance(&activator_clsid, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IStandardActivator, (void **)&activator);
    ok(hr == S_OK, "Create standard activator: %#lx.\n", hr);
    if (FAILED(hr)) goto uninitialize;
    hr = IStandardActivator_QueryInterface(activator, &IID_ISpecialSystemProperties, (void **)&properties);
    ok(hr == S_OK, "Get properties: %#lx.\n", hr);
    if (FAILED(hr)) { IStandardActivator_Release(activator); goto uninitialize; }
    ISpecialSystemProperties_SetSessionId(properties, 1, FALSE, TRUE);
    check_com(activator, 0x15, NULL, S_OK, 111);
    ISpecialSystemProperties_SetSessionId(properties, 2, FALSE, TRUE);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, S_OK, 222);
    check_com(activator, CLSCTX_LOCAL_SERVER, &server, E_NOTIMPL, 0);
    check_com(activator, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING, NULL, E_NOTIMPL, 0);
    ISpecialSystemProperties_SetClientImpersonating(properties, TRUE);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, E_NOTIMPL, 0);
    ISpecialSystemProperties_SetClientImpersonating(properties, FALSE);
    hr = IStandardActivator_StandardCreateInstance(activator, &clsid, NULL, CLSCTX_LOCAL_SERVER, NULL, 1, &result);
    ok(hr == E_NOTIMPL && !result.pItf, "Uncovered method lost its guard: %#lx.\n", hr);
    set_permission(appid_key, L"LaunchPermission", L"O:SYG:SYD:(D;;0x9;;;SY)(A;;0x1f;;;SY)");
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, E_ACCESSDENIED, 0);
    /* Ordinary session-1 user calls exercise current-session routing and
     * third-BOOL normalization through the same system broker. */
    set_permission(appid_key, L"LaunchPermission", L"O:SYG:SYD:(A;;0x1f;;;WD)");
    set_permission(machine_key, L"MachineLaunchRestriction", L"O:SYG:SYD:(A;;0x1f;;;WD)");
    GetModuleFileNameA(NULL, executable, ARRAY_SIZE(executable));
    StringFromGUID2(&clsid, guidW, ARRAY_SIZE(guidW));
    WideCharToMultiByte(CP_ACP, 0, guidW, -1, guid, sizeof(guid), NULL, NULL);
    sprintf(command, "\"%s\" session client %s", executable, guid);
    ok(CreateProcessAsUserA(first_token, NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &client),
       "Start ordinary COM client failed: %lu.\n", GetLastError());
    if (client.hProcess)
    {
        ok(WaitForSingleObject(client.hProcess, 20000) == WAIT_OBJECT_0, "User client timeout.\n");
        GetExitCodeProcess(client.hProcess, &status);
        ok(!status, "User client failed %lu.\n", status);
        if (status == STILL_ACTIVE) TerminateProcess(client.hProcess, 1);
        CloseHandle(client.hThread);
        CloseHandle(client.hProcess);
    }
    stop_publisher(&second);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, E_NOINTERFACE, 0);
    IStandardActivator_Reset(activator);
    check_com(activator, CLSCTX_LOCAL_SERVER, NULL, S_OK, 111);
    ISpecialSystemProperties_Release(properties);
    IStandardActivator_Release(activator);
uninitialize:
    CoUninitialize();
done:
    stop_publisher(&first);
    stop_publisher(&second);
}

static void test_selection(void)
{
    const WCHAR *allow = L"O:SYG:SYD:(A;;0x1f;;;SY)";
    const WCHAR *deny = L"O:SYG:SYD:(D;;0x9;;;SY)(A;;0x1f;;;SY)";
    struct saved_value machine = {0}, default_policy = {0};
    PROCESS_INFORMATION wrong = {0}, first = {0}, second = {0}, single = {0};
    PSID user = NULL, other = NULL;
    HANDLE first_token = NULL, second_token = NULL, wrong_token = NULL, replacement = NULL;
    WCHAR guid[40], class_path[128], appid_path[128];
    HKEY class_key;
    SECURITY_DESCRIPTOR_RELATIVE invalid = {SECURITY_DESCRIPTOR_REVISION};
    DWORD flags = 1;
    TOKEN_STATISTICS original_stats, replacement_stats;
    DWORD size, changed_session;
    HANDLE publisher_token;

    CoCreateGuid(&clsid);
    StringFromGUID2(&clsid, guid, ARRAY_SIZE(guid));
    swprintf(class_path, ARRAY_SIZE(class_path), L"Software\\Classes\\CLSID\\%s", guid);
    swprintf(appid_path, ARRAY_SIZE(appid_path), L"Software\\Classes\\AppID\\%s", guid);
    ok(!RegCreateKeyExW(HKEY_LOCAL_MACHINE, class_path, 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                       NULL, &class_key, NULL), "Create class policy.\n");
    ok(!RegSetValueExW(class_key, L"AppID", 0, REG_SZ, (BYTE *)guid, (wcslen(guid) + 1) * sizeof(WCHAR)),
       "Write class AppID.\n");
    RegCloseKey(class_key);
    ok(!RegCreateKeyExW(HKEY_LOCAL_MACHINE, appid_path, 0, NULL, 0, KEY_ALL_ACCESS | KEY_WOW64_64KEY,
                       NULL, &appid_key, NULL), "Create AppID policy.\n");
    ok(!RegSetValueExW(appid_key, L"RunAs", 0, REG_SZ, (BYTE *)L"Interactive User", sizeof(L"Interactive User")),
       "Write RunAs.\n");
    ok(!RegCreateKeyExW(HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Ole", 0, NULL, 0,
                       KEY_ALL_ACCESS | KEY_WOW64_64KEY, NULL, &machine_key, NULL), "Open machine policy.\n");
    save_value(L"MachineLaunchRestriction", &machine);
    save_value(L"DefaultLaunchPermission", &default_policy);
    set_permission(machine_key, L"MachineLaunchRestriction", allow);
    set_permission(machine_key, L"DefaultLaunchPermission", allow);
    set_permission(appid_key, L"LaunchPermission", allow);
    ConvertStringSidToSidW(L"S-1-5-21-101-202-303-1001", &user);
    ConvertStringSidToSidW(L"S-1-5-21-101-202-303-1002", &other);
    first_token = user_token(user, 1, TRUE);
    second_token = user_token(user, 2, TRUE);
    wrong_token = user_token(other, 1, FALSE);
    if (!first_token || !second_token || !wrong_token) goto done;
    /* The wrong identity is first in registry order and cannot become the
     * session authority because it has no INTERACTIVE group. */
    if (!start_publisher(wrong_token, 999, REGCLS_MULTIPLEUSE, &wrong) ||
        !start_publisher(first_token, 111, REGCLS_MULTIPLEUSE, &first) ||
        !start_publisher(second_token, 222, REGCLS_MULTIPLEUSE, &second)) goto done;
    replacement = user_token(user, 1, TRUE);
    if (!replacement) goto done;
    GetTokenInformation(first_token, TokenStatistics, &original_stats, sizeof(original_stats), &size);
    GetTokenInformation(replacement, TokenStatistics, &replacement_stats, sizeof(replacement_stats), &size);
    ok(memcmp(&original_stats.AuthenticationId, &replacement_stats.AuthenticationId, sizeof(LUID)),
       "Fixture did not distinguish authentication IDs.\n");
    check_class(1, CLSCTX_LOCAL_SERVER, S_OK, 111);
    check_class(2, 0x15, S_OK, 222);
    check_class(3, CLSCTX_LOCAL_SERVER, HRESULT_FROM_WIN32(ERROR_NO_SUCH_LOGON_SESSION), 0);
    if (OpenProcessToken(first.hProcess, TOKEN_ALL_ACCESS, &publisher_token))
    {
        changed_session = 3;
        ok(SetTokenInformation(publisher_token, TokenSessionId, &changed_session, sizeof(changed_session)),
           "Move publisher session: %lu.\n", GetLastError());
        check_class(1, CLSCTX_LOCAL_SERVER, E_NOINTERFACE, 0);
        check_class(3, CLSCTX_LOCAL_SERVER, E_NOINTERFACE, 0);
        changed_session = 1;
        ok(SetTokenInformation(publisher_token, TokenSessionId, &changed_session, sizeof(changed_session)),
           "Restore publisher session: %lu.\n", GetLastError());
        check_class(1, CLSCTX_LOCAL_SERVER, S_OK, 111);
        CloseHandle(publisher_token);
        /* Session reassignment replaces WTS lineage. Keep a separate live
         * authority after terminating the publisher later in this fixture. */
        ok(SetTokenInformation(replacement, TokenSessionId, &changed_session, sizeof(changed_session)),
           "Restore independent session authority: %lu.\n", GetLastError());
    }
    else ok(0, "Open publisher token failed: %lu.\n", GetLastError());
    check_class(~0u, CLSCTX_LOCAL_SERVER, E_NOTIMPL, 0);
    check_class(1, CLSCTX_INPROC_SERVER, E_NOTIMPL, 0);
    check_class(1, CLSCTX_LOCAL_SERVER | CLSCTX_ENABLE_CLOAKING, E_NOTIMPL, 0);
    set_permission(appid_key, L"LaunchPermission", deny);
    check_class(1, CLSCTX_LOCAL_SERVER, E_ACCESSDENIED, 0);
    set_permission(appid_key, L"LaunchPermission", allow);
    set_permission(machine_key, L"MachineLaunchRestriction", deny);
    check_class(1, CLSCTX_LOCAL_SERVER, E_ACCESSDENIED, 0);
    set_permission(machine_key, L"MachineLaunchRestriction", allow);
    set_permission(appid_key, L"LaunchPermission", L"O:SYG:SYD:(A;;0x1;;;SY)");
    check_class(1, CLSCTX_LOCAL_SERVER, S_OK, 111);
    set_permission(appid_key, L"LaunchPermission", L"O:SYG:SYD:(A;;0x3;;;SY)");
    check_class(1, CLSCTX_LOCAL_SERVER, E_ACCESSDENIED, 0);
    set_permission(appid_key, L"LaunchPermission", L"O:SYG:SYD:(A;;0x1;;;SY)(A;;0x9;;;WD)");
    check_class(1, CLSCTX_LOCAL_SERVER, E_NOTIMPL, 0);
    invalid.Control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
    invalid.Dacl = sizeof(invalid);
    RegSetValueExW(appid_key, L"LaunchPermission", 0, REG_BINARY, (BYTE *)&invalid, sizeof(invalid));
    check_class(1, CLSCTX_LOCAL_SERVER, HRESULT_FROM_WIN32(ERROR_INVALID_SECURITY_DESCR), 0);
    set_permission(appid_key, L"LaunchPermission", L"O:SYG:SYD:");
    check_class(1, CLSCTX_LOCAL_SERVER, E_ACCESSDENIED, 0);
    set_null_permission();
    check_class(1, CLSCTX_LOCAL_SERVER, S_OK, 111);
    set_callback_permission(FALSE, FALSE);
    check_class(1, CLSCTX_LOCAL_SERVER, E_NOTIMPL, 0);
    set_callback_permission(TRUE, FALSE);
    check_class(1, CLSCTX_LOCAL_SERVER, S_OK, 111);
    set_callback_permission(TRUE, TRUE);
    check_class(1, CLSCTX_LOCAL_SERVER, E_NOTIMPL, 0);
    set_permission(appid_key, L"LaunchPermission", L"O:SYG:SYD:(A;;0x1f;;;SY)S:(AU;SA;0x1;;;SY)");
    check_class(1, CLSCTX_LOCAL_SERVER, E_NOTIMPL, 0);
    RegDeleteValueW(appid_key, L"LaunchPermission");
    check_class(1, CLSCTX_LOCAL_SERVER, S_OK, 111);
    set_permission(machine_key, L"DefaultLaunchPermission", deny);
    check_class(1, CLSCTX_LOCAL_SERVER, E_ACCESSDENIED, 0);
    RegDeleteValueW(machine_key, L"DefaultLaunchPermission");
    check_class(1, CLSCTX_LOCAL_SERVER, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), 0);
    set_permission(machine_key, L"DefaultLaunchPermission", allow);
    RegDeleteValueW(machine_key, L"MachineLaunchRestriction");
    check_class(1, CLSCTX_LOCAL_SERVER, HRESULT_FROM_WIN32(ERROR_FILE_NOT_FOUND), 0);
    set_permission(machine_key, L"MachineLaunchRestriction", allow);
    RegSetValueExW(appid_key, L"AppIDFlags", 0, REG_DWORD, (BYTE *)&flags, sizeof(flags));
    check_class(1, CLSCTX_LOCAL_SERVER, E_NOTIMPL, 0);
    RegDeleteValueW(appid_key, L"AppIDFlags");
    RegSetValueExW(appid_key, L"LocalService", 0, REG_SZ, (BYTE *)L"fixture", sizeof(L"fixture"));
    check_class(1, CLSCTX_LOCAL_SERVER, E_NOTIMPL, 0);
    RegDeleteValueW(appid_key, L"LocalService");
    stop_publisher(&first);
    check_class(1, CLSCTX_LOCAL_SERVER, E_NOINTERFACE, 0);
    check_class(2, CLSCTX_LOCAL_SERVER, S_OK, 222);
    if (start_publisher(replacement, 333, REGCLS_SINGLEUSE, &single))
    {
        set_permission(machine_key, L"MachineLaunchRestriction", deny);
        check_class(1, CLSCTX_LOCAL_SERVER, E_ACCESSDENIED, 0);
        set_permission(machine_key, L"MachineLaunchRestriction", allow);
        check_class(1, CLSCTX_LOCAL_SERVER, S_OK, 333);
        check_class(1, CLSCTX_LOCAL_SERVER, E_NOINTERFACE, 0);
    }
    stop_publisher(&wrong);
    stop_publisher(&second);
    stop_publisher(&single);
    set_permission(appid_key, L"LaunchPermission", allow);
    test_com_selection(replacement, second_token);
done:
    stop_publisher(&wrong);
    stop_publisher(&first);
    stop_publisher(&second);
    stop_publisher(&single);
    if (replacement) CloseHandle(replacement);
    if (wrong_token) CloseHandle(wrong_token);
    if (second_token) CloseHandle(second_token);
    if (first_token) CloseHandle(first_token);
    LocalFree(user);
    LocalFree(other);
    restore_value(L"MachineLaunchRestriction", &machine);
    restore_value(L"DefaultLaunchPermission", &default_policy);
    RegCloseKey(machine_key);
    RegCloseKey(appid_key);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, class_path, KEY_WOW64_64KEY, 0);
    RegDeleteKeyExW(HKEY_LOCAL_MACHINE, appid_path, KEY_WOW64_64KEY, 0);
}

START_TEST(session)
{
    BYTE buffer[256];
    TOKEN_USER *user = (TOKEN_USER *)buffer;
    HANDLE token;
    DWORD size;
    BOOLEAN previous;
    NTSTATUS status;
    unsigned int i;
    const ULONG privileges[] = {SE_CREATE_TOKEN_PRIVILEGE, SE_ASSIGNPRIMARYTOKEN_PRIVILEGE,
                                SE_INCREASE_QUOTA_PRIVILEGE, SE_TCB_PRIVILEGE};
    char **argv;
    int argc = winetest_get_mainargs(&argv);

    if (strcmp(winetest_platform, "wine"))
    {
        win_skip("Wine-private scoped class registry protocol.\n");
        return;
    }
    if (argc == 7 && !strcmp(argv[2], "publisher"))
    {
        publisher(argv[3], argv[4], strtoul(argv[5], NULL, 10), strtoul(argv[6], NULL, 10));
        return;
    }
    if (argc == 4 && !strcmp(argv[2], "client"))
    {
        com_client(argv[3]);
        return;
    }
    if (!GetEnvironmentVariableA("LINUXNT_RPCSS_SESSION_FIXTURE", (char *)buffer, sizeof(buffer)))
    {
        win_skip("Requires an owned prefix and sealed LocalSystem bootstrap.\n");
        return;
    }
    ok(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token), "Open bootstrap identity.\n");
    if (!GetTokenInformation(token, TokenUser, buffer, sizeof(buffer), &size) ||
        !IsWellKnownSid(user->User.Sid, WinLocalSystemSid))
    {
        ok(0, "Fixture did not inherit genuine bootstrap LocalSystem identity.\n");
        CloseHandle(token);
        return;
    }
    CloseHandle(token);
    for (i = 0; i < ARRAY_SIZE(privileges); ++i)
    {
        status = RtlAdjustPrivilege(privileges[i], TRUE, FALSE, &previous);
        ok(!status, "Enable fixture privilege %lu returned %#lx.\n", privileges[i], status);
        if (status) return;
    }
    if (bind_rpcss() && start_rpcss())
    {
        test_selection();
        RpcBindingFree(&binding);
    }
}
