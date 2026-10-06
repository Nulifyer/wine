/* Unit test suite for Rtl* API functions
 *
 * Copyright 2003 Thomas Mertes
 * Copyright 2025 Zhiyi Zhang for CodeWeavers
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * NOTES
 * We use function pointers here as there is no import library for NTDLL on
 * windows.
 */

#include <stdlib.h>
#include <stdarg.h>

#include "ntstatus.h"
#define WIN32_NO_STATUS
#include "windef.h"
#include "winbase.h"
#include "winreg.h"
#include "winternl.h"
#include "in6addr.h"
#include "inaddr.h"
#include "ip2string.h"
#include "sddl.h"
#include "ddk/ntifs.h"
#include "wine/test.h"
#include "wine/asm.h"
#include "wine/rbtree.h"

#ifndef __WINE_WINTERNL_H

typedef struct _RTL_HANDLE
{
    struct _RTL_HANDLE * Next;
} RTL_HANDLE;

typedef struct _RTL_HANDLE_TABLE
{
    ULONG MaxHandleCount;
    ULONG HandleSize;
    ULONG Unused[2];
    PVOID NextFree;
    PVOID FirstHandle;
    PVOID ReservedMemory;
    PVOID MaxHandle;
} RTL_HANDLE_TABLE;

#endif

static BOOL is_win64 = (sizeof(void *) > sizeof(int));

/* avoid #include <winsock2.h> */
#undef htons
#ifdef WORDS_BIGENDIAN
#define htons(s) ((USHORT)(s))
#else  /* WORDS_BIGENDIAN */
static inline USHORT __my_ushort_swap(USHORT s)
{
    return (s >> 8) | (s << 8);
}
#define htons(s) __my_ushort_swap(s)
#endif  /* WORDS_BIGENDIAN */


#ifdef __ASM_USE_FASTCALL_WRAPPER
extern ULONG WINAPI wrap_fastcall_func1( void *func, ULONG a );
__ASM_STDCALL_FUNC( wrap_fastcall_func1, 8,
                   "popl %ecx\n\t"
                   "popl %eax\n\t"
                   "xchgl (%esp),%ecx\n\t"
                   "jmp *%eax" )
#define call_fastcall_func1(func,a) wrap_fastcall_func1(func,a)
#else
#define call_fastcall_func1(func,a) func(a)
#endif


/* Function ptrs for ntdll calls */
static HMODULE hntdll = 0;
static NTSTATUS  (WINAPI *pRtlAllocateAndInitializeSidEx)(PSID_IDENTIFIER_AUTHORITY,BYTE,PULONG,PSID *);
static PRTL_SPLAY_LINKS (WINAPI *pRtlDelete)(PRTL_SPLAY_LINKS);
static void      (WINAPI  *pRtlDeleteNoSplay)(PRTL_SPLAY_LINKS, PRTL_SPLAY_LINKS *);
static BOOLEAN   (WINAPI  *pRtlDeleteElementGenericTable)(PRTL_GENERIC_TABLE,PVOID);
static BOOLEAN   (WINAPI  *pRtlAreLongPathsEnabled)(void);
static BOOLEAN   (WINAPI  *pRtlDeleteElementGenericTableAvl)(PRTL_AVL_TABLE,PVOID);
static void *    (WINAPI  *pRtlEnumerateGenericTable)(PRTL_GENERIC_TABLE, BOOLEAN);
static void *    (WINAPI  *pRtlEnumerateGenericTableAvl)(PRTL_AVL_TABLE, BOOLEAN);
static void *    (WINAPI  *pRtlEnumerateGenericTableWithoutSplaying)(PRTL_GENERIC_TABLE, PVOID *);
static void *    (WINAPI  *pRtlEnumerateGenericTableWithoutSplayingAvl)(PRTL_AVL_TABLE, PVOID *);
static void *    (WINAPI  *pRtlInsertElementGenericTableAvl)(PRTL_AVL_TABLE, void *, ULONG, PBOOLEAN);
static BOOLEAN   (WINAPI  *pRtlIsGenericTableEmptyAvl)(PRTL_AVL_TABLE);
static void *    (WINAPI  *pRtlLookupElementGenericTableAvl)(PRTL_AVL_TABLE, void *);
static ULONG     (WINAPI  *pRtlNumberGenericTableElementsAvl)(PRTL_AVL_TABLE);
static VOID      (WINAPI  *pRtlMoveMemory)(LPVOID,LPCVOID,SIZE_T);
static VOID      (WINAPI  *pRtlFillMemory)(LPVOID,SIZE_T,BYTE);
static VOID      (WINAPI  *pRtlFillMemoryUlong)(LPVOID,SIZE_T,ULONG);
static VOID      (WINAPI  *pRtlZeroMemory)(LPVOID,SIZE_T);
static VOID      (WINAPI  *pRtlFlushHeaps)(void);
#ifdef __i386__
static USHORT    (FASTCALL *pRtlUshortByteSwap)(USHORT source);
static ULONG     (FASTCALL *pRtlUlongByteSwap)(ULONG source);
static ULONGLONG (FASTCALL *pRtlUlonglongByteSwap)(ULONGLONG source);
#endif
static void *    (WINAPI *pRtlGetElementGenericTable)(PRTL_GENERIC_TABLE, ULONG);
static DWORD     (WINAPI *pRtlGetThreadErrorMode)(void);
static NTSTATUS  (WINAPI *pRtlSetThreadErrorMode)(DWORD, LPDWORD);
static PVOID     (WINAPI *pRtlInsertElementGenericTable)(PRTL_GENERIC_TABLE, PVOID, CLONG, PBOOLEAN);
static PVOID     (WINAPI *pRtlInsertElementGenericTableAvl)(PRTL_AVL_TABLE, PVOID, ULONG, PBOOLEAN);
static NTSTATUS  (WINAPI *pRtlIpv4AddressToStringExA)(const IN_ADDR *, USHORT, LPSTR, PULONG);
static NTSTATUS  (WINAPI *pRtlIpv4StringToAddressExA)(PCSTR, BOOLEAN, IN_ADDR *, PUSHORT);
static NTSTATUS  (WINAPI *pRtlIpv6AddressToStringExA)(struct in6_addr *, ULONG, USHORT, PCHAR, PULONG);
static NTSTATUS  (WINAPI *pRtlIpv6StringToAddressExA)(PCSTR, struct in6_addr *, PULONG, PUSHORT);
static NTSTATUS  (WINAPI *pRtlIpv6StringToAddressExW)(PCWSTR, struct in6_addr *, PULONG, PUSHORT);
static BOOL      (WINAPI *pRtlIsCriticalSectionLocked)(CRITICAL_SECTION *);
static BOOL      (WINAPI *pRtlIsCriticalSectionLockedByThread)(CRITICAL_SECTION *);
static BOOLEAN   (WINAPI *pRtlIsGenericTableEmpty)(PRTL_GENERIC_TABLE);
static BOOLEAN   (WINAPI *pRtlIsGenericTableEmptyAvl)(PRTL_AVL_TABLE);
static NTSTATUS  (WINAPI *pRtlInitializeCriticalSectionEx)(CRITICAL_SECTION *, ULONG, ULONG);
static void      (WINAPI *pRtlInitializeGenericTable)(RTL_GENERIC_TABLE *, PRTL_GENERIC_COMPARE_ROUTINE,
                                                      PRTL_GENERIC_ALLOCATE_ROUTINE, PRTL_GENERIC_FREE_ROUTINE,
                                                      void *);
static void      (WINAPI *pRtlInitializeGenericTableAvl)(RTL_AVL_TABLE *, PRTL_AVL_COMPARE_ROUTINE,
                                                         PRTL_AVL_ALLOCATE_ROUTINE, PRTL_AVL_FREE_ROUTINE,
                                                         void *);
static void *    (WINAPI *pRtlFindExportedRoutineByName)(HMODULE,const char *);
static void *    (WINAPI *pRtlLookupElementGenericTable)(PRTL_GENERIC_TABLE, void *);
static void *    (WINAPI *pRtlLookupElementGenericTableAvl)(PRTL_AVL_TABLE, void *);
static ULONG     (WINAPI *pRtlNumberGenericTableElements)(PRTL_GENERIC_TABLE);
static ULONG     (WINAPI *pRtlNumberGenericTableElementsAvl)(PRTL_AVL_TABLE);
static NTSTATUS  (WINAPI *pLdrEnumerateLoadedModules)(void *, void *, void *);
static NTSTATUS  (WINAPI *pLdrRegisterDllNotification)(ULONG, PLDR_DLL_NOTIFICATION_FUNCTION, void *, void **);
static NTSTATUS  (WINAPI *pLdrUnregisterDllNotification)(void *);
static VOID      (WINAPI *pRtlGetDeviceFamilyInfoEnum)(ULONGLONG *,DWORD *,DWORD *);
static void      (WINAPI *pRtlRbInsertNodeEx)(RTL_RB_TREE *, RTL_BALANCED_NODE *, BOOLEAN, RTL_BALANCED_NODE *);
static void      (WINAPI *pRtlRbRemoveNode)(RTL_RB_TREE *, RTL_BALANCED_NODE *);
static DWORD     (WINAPI *pRtlConvertDeviceFamilyInfoToString)(DWORD *, DWORD *, WCHAR *, WCHAR *);
static NTSTATUS  (WINAPI *pRtlCopySecurityDescriptor)(PSECURITY_DESCRIPTOR,PSECURITY_DESCRIPTOR *);
static NTSTATUS  (WINAPI *pRtlCreateAndSetSD)(PRTL_ACE_DATA,ULONG,PSID,PSID,PSECURITY_DESCRIPTOR *);
static NTSTATUS  (WINAPI *pRtlCreateUserSecurityObject)(PRTL_ACE_DATA,ULONG,PSID,PSID,BOOLEAN,PGENERIC_MAPPING,PSECURITY_DESCRIPTOR *);
static NTSTATUS  (WINAPI *pRtlGetAcesBufferSize)(PACL,PULONG);
static NTSTATUS  (WINAPI *pRtlCreateServiceSid)(PUNICODE_STRING, PSID, PULONG);
static NTSTATUS  (WINAPI *pRtlDeriveCapabilitySidsFromName)(UNICODE_STRING *, PSID, PSID);
static NTSTATUS  (WINAPI *pRtlCapabilityCheck)(HANDLE, UNICODE_STRING *, BOOLEAN *);
static NTSTATUS  (WINAPI *pRtlCheckTokenCapability)(HANDLE, PSID, BOOLEAN *);
static NTSTATUS  (WINAPI *pRtlSidHashInitialize)(SID_AND_ATTRIBUTES *, ULONG, SID_AND_ATTRIBUTES_HASH *);
static SID_AND_ATTRIBUTES * (WINAPI *pRtlSidHashLookup)(SID_AND_ATTRIBUTES_HASH *, PSID);
static BOOLEAN   (WINAPI *pRtlTestProtectedAccess)(UCHAR, UCHAR);
static BOOLEAN   (WINAPI *pRtlValidProcessProtection)(UCHAR);
static NTSTATUS  (WINAPI *pRtlInitializeNtUserPfn)( const UINT64 *client_procsA, ULONG procsA_size,
                                                    const UINT64 *client_procsW, ULONG procsW_size,
                                                    const void *client_workers, ULONG workers_size );
static PRTL_SPLAY_LINKS (WINAPI *pRtlRealPredecessor)(PRTL_SPLAY_LINKS);
static PRTL_SPLAY_LINKS (WINAPI *pRtlRealSuccessor)(PRTL_SPLAY_LINKS);
static NTSTATUS  (WINAPI *pRtlRetrieveNtUserPfn)( const UINT64 **client_procsA,
                                                  const UINT64 **client_procsW,
                                                  const UINT64 **client_workers );
static NTSTATUS  (WINAPI *pRtlResetNtUserPfn)(void);
static PRTL_SPLAY_LINKS (WINAPI *pRtlSubtreePredecessor)(PRTL_SPLAY_LINKS);
static PRTL_SPLAY_LINKS (WINAPI *pRtlSubtreeSuccessor)(PRTL_SPLAY_LINKS);
static PRTL_SPLAY_LINKS (WINAPI *pRtlSplay)(PRTL_SPLAY_LINKS);

static HMODULE hkernel32 = 0;
static BOOL      (WINAPI *pIsWow64Process)(HANDLE, PBOOL);


#define LEN 16
static const char* src_src = "This is a test!"; /* 16 bytes long, incl NUL */
static WCHAR ws2_32dllW[] = {'w','s','2','_','3','2','.','d','l','l',0};
static WCHAR nsidllW[]    = {'n','s','i','.','d','l','l',0};
static WCHAR wintrustdllW[] = {'w','i','n','t','r','u','s','t','.','d','l','l',0};
static WCHAR crypt32dllW[] = {'c','r','y','p','t','3','2','.','d','l','l',0};
static ULONG src_aligned_block[4];
static ULONG dest_aligned_block[32];
static const char *src = (const char*)src_aligned_block;
static char* dest = (char*)dest_aligned_block;
const WCHAR *expected_dll = nsidllW;

static void InitFunctionPtrs(void)
{
    hntdll = LoadLibraryA("ntdll.dll");
    ok(hntdll != 0, "LoadLibrary failed\n");
    if (hntdll) {
        pRtlAllocateAndInitializeSidEx = (void *)GetProcAddress(hntdll, "RtlAllocateAndInitializeSidEx");
        pRtlDelete = (void *)GetProcAddress(hntdll, "RtlDelete");
        pRtlDeleteElementGenericTable = (void *)GetProcAddress(hntdll, "RtlDeleteElementGenericTable");
        pRtlAreLongPathsEnabled = (void *)GetProcAddress(hntdll, "RtlAreLongPathsEnabled");
        pRtlDeleteElementGenericTableAvl = (void *)GetProcAddress(hntdll, "RtlDeleteElementGenericTableAvl");
        pRtlDeleteNoSplay = (void *)GetProcAddress(hntdll, "RtlDeleteNoSplay");
        pRtlEnumerateGenericTable = (void *)GetProcAddress(hntdll, "RtlEnumerateGenericTable");
        pRtlEnumerateGenericTableAvl = (void *)GetProcAddress(hntdll, "RtlEnumerateGenericTableAvl");
        pRtlEnumerateGenericTableWithoutSplaying = (void *)GetProcAddress(hntdll, "RtlEnumerateGenericTableWithoutSplaying");
        pRtlEnumerateGenericTableWithoutSplayingAvl = (void *)GetProcAddress(hntdll, "RtlEnumerateGenericTableWithoutSplayingAvl");
        pRtlInsertElementGenericTableAvl = (void *)GetProcAddress(hntdll, "RtlInsertElementGenericTableAvl");
        pRtlIsGenericTableEmptyAvl = (void *)GetProcAddress(hntdll, "RtlIsGenericTableEmptyAvl");
        pRtlLookupElementGenericTableAvl = (void *)GetProcAddress(hntdll, "RtlLookupElementGenericTableAvl");
        pRtlNumberGenericTableElementsAvl = (void *)GetProcAddress(hntdll, "RtlNumberGenericTableElementsAvl");
	pRtlMoveMemory = (void *)GetProcAddress(hntdll, "RtlMoveMemory");
	pRtlFillMemory = (void *)GetProcAddress(hntdll, "RtlFillMemory");
	pRtlFillMemoryUlong = (void *)GetProcAddress(hntdll, "RtlFillMemoryUlong");
	pRtlZeroMemory = (void *)GetProcAddress(hntdll, "RtlZeroMemory");
        pRtlFlushHeaps = (void *)GetProcAddress(hntdll, "RtlFlushHeaps");
#ifdef __i386__
        pRtlUshortByteSwap = (void *)GetProcAddress(hntdll, "RtlUshortByteSwap");
        pRtlUlongByteSwap = (void *)GetProcAddress(hntdll, "RtlUlongByteSwap");
        pRtlUlonglongByteSwap = (void *)GetProcAddress(hntdll, "RtlUlonglongByteSwap");
#endif
        pRtlGetElementGenericTable = (void *)GetProcAddress(hntdll, "RtlGetElementGenericTable");
        pRtlGetThreadErrorMode = (void *)GetProcAddress(hntdll, "RtlGetThreadErrorMode");
        pRtlSetThreadErrorMode = (void *)GetProcAddress(hntdll, "RtlSetThreadErrorMode");
        pRtlInsertElementGenericTable = (void *)GetProcAddress(hntdll, "RtlInsertElementGenericTable");
        pRtlInsertElementGenericTableAvl = (void *)GetProcAddress(hntdll, "RtlInsertElementGenericTableAvl");
        pRtlIpv4AddressToStringExA = (void *)GetProcAddress(hntdll, "RtlIpv4AddressToStringExA");
        pRtlIpv4StringToAddressExA = (void *)GetProcAddress(hntdll, "RtlIpv4StringToAddressExA");
        pRtlIpv6AddressToStringExA = (void *)GetProcAddress(hntdll, "RtlIpv6AddressToStringExA");
        pRtlIpv6StringToAddressExA = (void *)GetProcAddress(hntdll, "RtlIpv6StringToAddressExA");
        pRtlIpv6StringToAddressExW = (void *)GetProcAddress(hntdll, "RtlIpv6StringToAddressExW");
        pRtlIsCriticalSectionLocked = (void *)GetProcAddress(hntdll, "RtlIsCriticalSectionLocked");
        pRtlIsCriticalSectionLockedByThread = (void *)GetProcAddress(hntdll, "RtlIsCriticalSectionLockedByThread");
        pRtlIsGenericTableEmpty = (void *)GetProcAddress(hntdll, "RtlIsGenericTableEmpty");
        pRtlIsGenericTableEmptyAvl = (void *)GetProcAddress(hntdll, "RtlIsGenericTableEmptyAvl");
        pRtlInitializeCriticalSectionEx = (void *)GetProcAddress(hntdll, "RtlInitializeCriticalSectionEx");
        pRtlInitializeGenericTable = (void *)GetProcAddress(hntdll, "RtlInitializeGenericTable");
        pRtlInitializeGenericTableAvl = (void *)GetProcAddress(hntdll, "RtlInitializeGenericTableAvl");
        pRtlFindExportedRoutineByName = (void *)GetProcAddress(hntdll, "RtlFindExportedRoutineByName");
        pRtlLookupElementGenericTable = (void *)GetProcAddress(hntdll, "RtlLookupElementGenericTable");
        pRtlLookupElementGenericTableAvl = (void *)GetProcAddress(hntdll, "RtlLookupElementGenericTableAvl");
        pRtlNumberGenericTableElements = (void *)GetProcAddress(hntdll, "RtlNumberGenericTableElements");
        pRtlNumberGenericTableElementsAvl = (void *)GetProcAddress(hntdll, "RtlNumberGenericTableElementsAvl");
        pLdrEnumerateLoadedModules = (void *)GetProcAddress(hntdll, "LdrEnumerateLoadedModules");
        pLdrRegisterDllNotification = (void *)GetProcAddress(hntdll, "LdrRegisterDllNotification");
        pLdrUnregisterDllNotification = (void *)GetProcAddress(hntdll, "LdrUnregisterDllNotification");
        pRtlCreateServiceSid = (void *)GetProcAddress(hntdll, "RtlCreateServiceSid");
        pRtlDeriveCapabilitySidsFromName = (void *)GetProcAddress(hntdll, "RtlDeriveCapabilitySidsFromName");
        pRtlCapabilityCheck = (void *)GetProcAddress(hntdll, "RtlCapabilityCheck");
        pRtlCheckTokenCapability = (void *)GetProcAddress(hntdll, "RtlCheckTokenCapability");
        pRtlSidHashInitialize = (void *)GetProcAddress(hntdll, "RtlSidHashInitialize");
        pRtlSidHashLookup = (void *)GetProcAddress(hntdll, "RtlSidHashLookup");
        pRtlTestProtectedAccess = (void *)GetProcAddress(hntdll, "RtlTestProtectedAccess");
        pRtlValidProcessProtection = (void *)GetProcAddress(hntdll, "RtlValidProcessProtection");
        pRtlGetDeviceFamilyInfoEnum = (void *)GetProcAddress(hntdll, "RtlGetDeviceFamilyInfoEnum");
        pRtlRbInsertNodeEx = (void *)GetProcAddress(hntdll, "RtlRbInsertNodeEx");
        pRtlRbRemoveNode = (void *)GetProcAddress(hntdll, "RtlRbRemoveNode");
        pRtlConvertDeviceFamilyInfoToString = (void *)GetProcAddress(hntdll, "RtlConvertDeviceFamilyInfoToString");
        pRtlCopySecurityDescriptor = (void *)GetProcAddress(hntdll, "RtlCopySecurityDescriptor");
        pRtlCreateAndSetSD = (void *)GetProcAddress(hntdll, "RtlCreateAndSetSD");
        pRtlCreateUserSecurityObject = (void *)GetProcAddress(hntdll, "RtlCreateUserSecurityObject");
        pRtlGetAcesBufferSize = (void *)GetProcAddress(hntdll, "RtlGetAcesBufferSize");
        pRtlInitializeNtUserPfn = (void *)GetProcAddress(hntdll, "RtlInitializeNtUserPfn");
        pRtlRealPredecessor = (void *)GetProcAddress(hntdll, "RtlRealPredecessor");
        pRtlRealSuccessor = (void *)GetProcAddress(hntdll, "RtlRealSuccessor");
        pRtlRetrieveNtUserPfn = (void *)GetProcAddress(hntdll, "RtlRetrieveNtUserPfn");
        pRtlResetNtUserPfn = (void *)GetProcAddress(hntdll, "RtlResetNtUserPfn");
        pRtlSubtreePredecessor = (void *)GetProcAddress(hntdll, "RtlSubtreePredecessor");
        pRtlSubtreeSuccessor = (void *)GetProcAddress(hntdll, "RtlSubtreeSuccessor");
        pRtlSplay = (void *)GetProcAddress(hntdll, "RtlSplay");
    }
    hkernel32 = LoadLibraryA("kernel32.dll");
    ok(hkernel32 != 0, "LoadLibrary failed\n");
    if (hkernel32) {
        pIsWow64Process = (void *)GetProcAddress(hkernel32, "IsWow64Process");
    }
    strcpy((char*)src_aligned_block, src_src);
    ok(strlen(src) == 15, "Source must be 16 bytes long!\n");
}

static void test_RtlQueryProcessDebugInformation(void)
{
    DEBUG_BUFFER *buffer;
    NTSTATUS status;

    /* PDI_HEAPS | PDI_HEAP_BLOCKS */
    buffer = RtlCreateQueryDebugBuffer( 0, 0 );
    ok( buffer != NULL, "RtlCreateQueryDebugBuffer returned NULL" );

    status = RtlQueryProcessDebugInformation( GetCurrentThreadId(), PDI_HEAPS | PDI_HEAP_BLOCKS, buffer );
    ok( status == STATUS_INVALID_CID, "RtlQueryProcessDebugInformation returned %lx\n", status );

    status = RtlQueryProcessDebugInformation( GetCurrentProcessId(), PDI_HEAPS | PDI_HEAP_BLOCKS, buffer );
    ok( !status, "RtlQueryProcessDebugInformation returned %lx\n", status );
    ok( buffer->InfoClassMask == (PDI_HEAPS | PDI_HEAP_BLOCKS), "unexpected InfoClassMask %ld\n", buffer->InfoClassMask);
    ok( buffer->HeapInformation != NULL, "unexpected HeapInformation %p\n", buffer->HeapInformation);

    status = RtlDestroyQueryDebugBuffer( buffer );
    ok( !status, "RtlDestroyQueryDebugBuffer returned %lx\n", status );

    /* PDI_MODULES */
    buffer = RtlCreateQueryDebugBuffer( 0, 0 );
    ok( buffer != NULL, "RtlCreateQueryDebugBuffer returned NULL" );

    status = RtlQueryProcessDebugInformation( GetCurrentProcessId(), PDI_MODULES, buffer );
    ok( !status, "RtlQueryProcessDebugInformation returned %lx\n", status );
    ok( buffer->InfoClassMask == PDI_MODULES, "unexpected InfoClassMask %ld\n", buffer->InfoClassMask);
    ok( buffer->ModuleInformation != NULL, "unexpected ModuleInformation %p\n", buffer->ModuleInformation);

    status = RtlDestroyQueryDebugBuffer( buffer );
    ok( !status, "RtlDestroyQueryDebugBuffer returned %lx\n", status );
}

#define COMP(str1,str2,cmplen,len) size = RtlCompareMemory(str1, str2, cmplen); \
  ok(size == len, "Expected %Id, got %Id\n", size, (SIZE_T)len)

static void test_RtlCompareMemory(void)
{
  SIZE_T size;

  strcpy(dest, src);

  COMP(src,src,0,0);
  COMP(src,src,LEN,LEN);
  dest[0] = 'x';
  COMP(src,dest,LEN,0);
}

static void test_RtlCompareMemoryUlong(void)
{
    ULONG a[10];
    ULONG result;

    a[0]= 0x0123;
    a[1]= 0x4567;
    a[2]= 0x89ab;
    a[3]= 0xcdef;
    result = RtlCompareMemoryUlong(a, 0, 0x0123);
    ok(result == 0, "RtlCompareMemoryUlong(%p, 0, 0x0123) returns %lu, expected 0\n", a, result);
    result = RtlCompareMemoryUlong(a, 3, 0x0123);
    ok(result == 0, "RtlCompareMemoryUlong(%p, 3, 0x0123) returns %lu, expected 0\n", a, result);
    result = RtlCompareMemoryUlong(a, 4, 0x0123);
    ok(result == 4, "RtlCompareMemoryUlong(%p, 4, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 5, 0x0123);
    ok(result == 4 || !result /* arm64 */, "RtlCompareMemoryUlong(%p, 5, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 7, 0x0123);
    ok(result == 4 || !result /* arm64 */, "RtlCompareMemoryUlong(%p, 7, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 8, 0x0123);
    ok(result == 4, "RtlCompareMemoryUlong(%p, 8, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 9, 0x0123);
    ok(result == 4 || !result /* arm64 */, "RtlCompareMemoryUlong(%p, 9, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 4, 0x0127);
    ok(result == 0, "RtlCompareMemoryUlong(%p, 4, 0x0127) returns %lu, expected 0\n", a, result);
    result = RtlCompareMemoryUlong(a, 4, 0x7123);
    ok(result == 0 || result == 1 /* arm64 */, "RtlCompareMemoryUlong(%p, 4, 0x7123) returns %lu, expected 0\n", a, result);
    result = RtlCompareMemoryUlong(a, 16, 0x4567);
    ok(result == 0, "RtlCompareMemoryUlong(%p, 16, 0x4567) returns %lu, expected 0\n", a, result);

    a[1]= 0x0123;
    result = RtlCompareMemoryUlong(a, 3, 0x0123);
    ok(result == 0, "RtlCompareMemoryUlong(%p, 3, 0x0123) returns %lu, expected 0\n", a, result);
    result = RtlCompareMemoryUlong(a, 4, 0x0123);
    ok(result == 4, "RtlCompareMemoryUlong(%p, 4, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 5, 0x0123);
    ok(result == 4 || !result /* arm64 */, "RtlCompareMemoryUlong(%p, 5, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 7, 0x0123);
    ok(result == 4 || !result /* arm64 */, "RtlCompareMemoryUlong(%p, 7, 0x0123) returns %lu, expected 4\n", a, result);
    result = RtlCompareMemoryUlong(a, 8, 0x0123);
    ok(result == 8, "RtlCompareMemoryUlong(%p, 8, 0x0123) returns %lu, expected 8\n", a, result);
    result = RtlCompareMemoryUlong(a, 9, 0x0123);
    ok(result == 8 || !result /* arm64 */, "RtlCompareMemoryUlong(%p, 9, 0x0123) returns %lu, expected 8\n", a, result);
}

#define COPY(len) memset(dest,0,sizeof(dest_aligned_block)); pRtlMoveMemory(dest, src, len)
#define CMP(str) ok(strcmp(dest,str) == 0, "Expected '%s', got '%s'\n", str, dest)

static void test_RtlMoveMemory(void)
{
  if (!pRtlMoveMemory)
  {
    win_skip("RtlMoveMemory is not available\n");
    return;
  }

  /* Length should be in bytes and not rounded. Use strcmp to ensure we
   * didn't write past the end (it checks for the final NUL left by memset)
   */
  COPY(0); CMP("");
  COPY(1); CMP("T");
  COPY(2); CMP("Th");
  COPY(3); CMP("Thi");
  COPY(4); CMP("This");
  COPY(5); CMP("This ");
  COPY(6); CMP("This i");
  COPY(7); CMP("This is");
  COPY(8); CMP("This is ");
  COPY(9); CMP("This is a");

  /* Overlapping */
  strcpy(dest, src); pRtlMoveMemory(dest, dest + 1, strlen(src) - 1);
  CMP("his is a test!!");
  strcpy(dest, src); pRtlMoveMemory(dest + 1, dest, strlen(src));
  CMP("TThis is a test!");
}

#define FILL(len) memset(dest,0,sizeof(dest_aligned_block)); strcpy(dest, src); pRtlFillMemory(dest,len,'x')

static void test_RtlFillMemory(void)
{
  if (!pRtlFillMemory)
  {
    win_skip("RtlFillMemory is not available\n");
    return;
  }

  /* Length should be in bytes and not rounded. Use strcmp to ensure we
   * didn't write past the end (the remainder of the string should match)
   */
  FILL(0); CMP("This is a test!");
  FILL(1); CMP("xhis is a test!");
  FILL(2); CMP("xxis is a test!");
  FILL(3); CMP("xxxs is a test!");
  FILL(4); CMP("xxxx is a test!");
  FILL(5); CMP("xxxxxis a test!");
  FILL(6); CMP("xxxxxxs a test!");
  FILL(7); CMP("xxxxxxx a test!");
  FILL(8); CMP("xxxxxxxxa test!");
  FILL(9); CMP("xxxxxxxxx test!");
}

#define LFILL(len) memset(dest,0,sizeof(dest_aligned_block)); strcpy(dest, src); pRtlFillMemoryUlong(dest,len,val)

static void test_RtlFillMemoryUlong(void)
{
  ULONG val = ('x' << 24) | ('x' << 16) | ('x' << 8) | 'x';
  if (!pRtlFillMemoryUlong)
  {
    win_skip("RtlFillMemoryUlong is not available\n");
    return;
  }

  /* Length should be in bytes and not rounded. Use strcmp to ensure we
   * didn't write past the end (the remainder of the string should match)
   */
  LFILL(0); CMP("This is a test!");
  LFILL(1); CMP("This is a test!");
  LFILL(2); CMP("This is a test!");
  LFILL(3); CMP("This is a test!");
  LFILL(4); CMP("xxxx is a test!");
  LFILL(5); CMP("xxxx is a test!");
  LFILL(6); CMP("xxxx is a test!");
  LFILL(7); CMP("xxxx is a test!");
  LFILL(8); CMP("xxxxxxxxa test!");
  LFILL(9); CMP("xxxxxxxxa test!");
}

#define ZERO(len) memset(dest,0,sizeof(dest_aligned_block)); strcpy(dest, src); pRtlZeroMemory(dest,len)
#define MCMP(str) ok(memcmp(dest,str,LEN) == 0, "Memcmp failed\n")

static void test_RtlZeroMemory(void)
{
  if (!pRtlZeroMemory)
  {
    win_skip("RtlZeroMemory is not available\n");
    return;
  }

  /* Length should be in bytes and not rounded. */
  ZERO(0); MCMP("This is a test!");
  ZERO(1); MCMP("\0his is a test!");
  ZERO(2); MCMP("\0\0is is a test!");
  ZERO(3); MCMP("\0\0\0s is a test!");
  ZERO(4); MCMP("\0\0\0\0 is a test!");
  ZERO(5); MCMP("\0\0\0\0\0is a test!");
  ZERO(6); MCMP("\0\0\0\0\0\0s a test!");
  ZERO(7); MCMP("\0\0\0\0\0\0\0 a test!");
  ZERO(8); MCMP("\0\0\0\0\0\0\0\0a test!");
  ZERO(9); MCMP("\0\0\0\0\0\0\0\0\0 test!");
}

static void test_RtlByteSwap(void)
{
    ULONGLONG llresult;
    ULONG     lresult;
    USHORT    sresult;

#ifndef __i386__
    /* the Rtl*ByteSwap() are always inlined and not exported from ntdll on 64bit */
    sresult = RtlUshortByteSwap( 0x1234 );
    ok( 0x3412 == sresult,
        "inlined RtlUshortByteSwap() returns 0x%x\n", sresult );
    lresult = RtlUlongByteSwap( 0x87654321 );
    ok( 0x21436587 == lresult,
        "inlined RtlUlongByteSwap() returns 0x%lx\n", lresult );
    llresult = RtlUlonglongByteSwap( 0x7654321087654321ull );
    ok( 0x2143658710325476 == llresult,
        "inlined RtlUlonglongByteSwap() returns %#I64x\n", llresult );
#else
    ok( pRtlUshortByteSwap != NULL, "RtlUshortByteSwap is not available\n" );
    if ( pRtlUshortByteSwap )
    {
        sresult = call_fastcall_func1( pRtlUshortByteSwap, 0x1234u );
        ok( 0x3412u == sresult,
            "ntdll.RtlUshortByteSwap() returns %#x\n", sresult );
    }

    ok( pRtlUlongByteSwap != NULL, "RtlUlongByteSwap is not available\n" );
    if ( pRtlUlongByteSwap )
    {
        lresult = call_fastcall_func1( pRtlUlongByteSwap, 0x87654321ul );
        ok( 0x21436587ul == lresult,
            "ntdll.RtlUlongByteSwap() returns %#lx\n", lresult );
    }

    ok( pRtlUlonglongByteSwap != NULL, "RtlUlonglongByteSwap is not available\n");
    if ( pRtlUlonglongByteSwap )
    {
        llresult = pRtlUlonglongByteSwap( 0x7654321087654321ull );
        ok( 0x2143658710325476ull == llresult,
            "ntdll.RtlUlonglongByteSwap() returns %#I64x\n", llresult );
    }
#endif
}


static void test_RtlUniform(void)
{
    const ULONG step = 0x7fff;
    ULONG num;
    ULONG seed;
    ULONG seed_bak;
    ULONG expected;
    ULONG result;

    /*
     * According to the documentation RtlUniform is using D.H. Lehmer's 1948
     * algorithm.  We assume a more generic version of this algorithm,
     * which is the linear congruential generator (LCG).  Its formula is:
     *
     *   X_(n+1) = (a * X_n + c) % m
     *
     * where a is the multiplier, c is the increment, and m is the modulus.
     *
     * According to the documentation, the random numbers are distributed over
     * [0..MAXLONG].  Therefore, the modulus is MAXLONG + 1:
     *
     *   X_(n+1) = (a * X_n + c) % (MAXLONG + 1)
     *
     * To find out the increment, we just call RtlUniform with seed set to 0.
     * This reveals c = 0x7fffffc3.
     */
    seed = 0;
    expected = 0x7fffffc3;
    result = RtlUniform(&seed);
    ok(result == expected,
        "RtlUniform(&seed (seed == 0)) returns %lx, expected %lx\n",
        result, expected);

    /*
     * The formula is now:
     *
     *   X_(n+1) = (a * X_n + 0x7fffffc3) % (MAXLONG + 1)
     *
     * If the modulus is correct, RtlUniform(0) shall equal RtlUniform(MAXLONG + 1).
     * However, testing reveals that this is not the case.
     * That is, the modulus in the documentation is incorrect.
     */
    seed = 0x80000000U;
    expected = 0x7fffffb1;
    result = RtlUniform(&seed);

    ok(result == expected,
        "RtlUniform(&seed (seed == 0x80000000)) returns %lx, expected %lx\n",
        result, expected);

    /*
     * We try another value for modulus, say MAXLONG.
     * We discover that RtlUniform(0) equals RtlUniform(MAXLONG), which means
     * the correct value for the modulus is actually MAXLONG.
     */
    seed = 0x7fffffff;
    expected = 0x7fffffc3;
    result = RtlUniform(&seed);
    ok(result == expected,
        "RtlUniform(&seed (seed == 0x7fffffff)) returns %lx, expected %lx\n",
        result, expected);

    /*
     * The formula is now:
     *
     *   X_(n+1) = (a * X_n + 0x7fffffc3) % MAXLONG
     *
     * To find out the multiplier we can use:
     *
     *   a = RtlUniform(1) - 0x7fffffc3 (mod MAXLONG)
     *
     * This way, we find out that a = -18 (mod MAXLONG),
     * which is congruent to 0x7fffffed (MAXLONG - 18).
     */
    seed = 1;
    expected = ((ULONGLONG)seed * 0x7fffffed + 0x7fffffc3) % MAXLONG;
    result = RtlUniform(&seed);
    ok(result == expected,
        "RtlUniform(&seed (seed == 1)) returns %lx, expected %lx\n",
        result, expected);

    num = 2;
    do
    {
        seed = num;
        expected = ((ULONGLONG)seed * 0x7fffffed + 0x7fffffc3) % 0x7fffffff;
        result = RtlUniform(&seed);
        ok(result == expected,
                "test: RtlUniform(&seed (seed == %lx)) returns %lx, expected %lx\n",
                num, result, expected);
        ok(seed == expected,
                "test: RtlUniform(&seed (seed == %lx)) sets seed to %lx, expected %lx\n",
                num, result, expected);

        num += step;
    } while (num >= 2 + step);

    seed = 0;
    for (num = 0; num <= 100000; num++) {
        expected = ((ULONGLONG)seed * 0x7fffffed + 0x7fffffc3) % 0x7fffffff;
        seed_bak = seed;
        result = RtlUniform(&seed);
        ok(result == expected,
                "test: %ld RtlUniform(&seed (seed == %lx)) returns %lx, expected %lx\n",
                num, seed_bak, result, expected);
        ok(seed == expected,
                "test: %ld RtlUniform(&seed (seed == %lx)) sets seed to %lx, expected %lx\n",
                num, seed_bak, result, expected);
    } /* for */
}


static void test_RtlRandom(void)
{
    int i, j;
    ULONG seed;
    ULONG res[512];

    seed = 0;
    for (i = 0; i < ARRAY_SIZE(res); i++)
    {
        res[i] = RtlRandom(&seed);
        ok(seed != res[i], "%i: seed is same as res %lx\n", i, seed);
        for (j = 0; j < i; j++)
            ok(res[i] != res[j], "res[%i] (%lx) is same as res[%i] (%lx)\n", j, res[j], i, res[i]);
    }
}


typedef struct {
    ACCESS_MASK GrantedAccess;
    ACCESS_MASK DesiredAccess;
    BOOLEAN result;
} all_accesses_t;

static const all_accesses_t all_accesses[] = {
    {0xFEDCBA76, 0xFEDCBA76, 1},
    {0x00000000, 0xFEDCBA76, 0},
    {0xFEDCBA76, 0x00000000, 1},
    {0x00000000, 0x00000000, 1},
    {0xFEDCBA76, 0xFEDCBA70, 1},
    {0xFEDCBA70, 0xFEDCBA76, 0},
    {0xFEDCBA76, 0xFEDC8A76, 1},
    {0xFEDC8A76, 0xFEDCBA76, 0},
    {0xFEDCBA76, 0xC8C4B242, 1},
    {0xC8C4B242, 0xFEDCBA76, 0},
};


static void test_RtlAreAllAccessesGranted(void)
{
    unsigned int test_num;
    BOOLEAN result;

    for (test_num = 0; test_num < ARRAY_SIZE(all_accesses); test_num++) {
	result = RtlAreAllAccessesGranted(all_accesses[test_num].GrantedAccess,
					  all_accesses[test_num].DesiredAccess);
	ok(all_accesses[test_num].result == result,
           "(test %d): RtlAreAllAccessesGranted(%08lx, %08lx) returns %d, expected %d\n",
	   test_num, all_accesses[test_num].GrantedAccess,
	   all_accesses[test_num].DesiredAccess,
	   result, all_accesses[test_num].result);
    } /* for */
}


typedef struct {
    ACCESS_MASK GrantedAccess;
    ACCESS_MASK DesiredAccess;
    BOOLEAN result;
} any_accesses_t;

static const any_accesses_t any_accesses[] = {
    {0xFEDCBA76, 0xFEDCBA76, 1},
    {0x00000000, 0xFEDCBA76, 0},
    {0xFEDCBA76, 0x00000000, 0},
    {0x00000000, 0x00000000, 0},
    {0xFEDCBA76, 0x01234589, 0},
    {0x00040000, 0xFEDCBA76, 1},
    {0x00040000, 0xFED8BA76, 0},
    {0xFEDCBA76, 0x00040000, 1},
    {0xFED8BA76, 0x00040000, 0},
};


static void test_RtlAreAnyAccessesGranted(void)
{
    unsigned int test_num;
    BOOLEAN result;

    for (test_num = 0; test_num < ARRAY_SIZE(any_accesses); test_num++) {
	result = RtlAreAnyAccessesGranted(any_accesses[test_num].GrantedAccess,
					  any_accesses[test_num].DesiredAccess);
	ok(any_accesses[test_num].result == result,
           "(test %d): RtlAreAnyAccessesGranted(%08lx, %08lx) returns %d, expected %d\n",
	   test_num, any_accesses[test_num].GrantedAccess,
	   any_accesses[test_num].DesiredAccess,
	   result, any_accesses[test_num].result);
    } /* for */
}

static void test_RtlAreLongPathsEnabled(void)
{
    PEB *peb = NtCurrentTeb()->Peb;
    BOOLEAN old_value;

    if (!pRtlAreLongPathsEnabled)
    {
        win_skip( "RtlAreLongPathsEnabled is unavailable\n" );
        return;
    }

    old_value = peb->IsLongPathAwareProcess;
    peb->IsLongPathAwareProcess = FALSE;
    ok( !pRtlAreLongPathsEnabled(), "expected long paths to be disabled\n" );
    peb->IsLongPathAwareProcess = TRUE;
    ok( pRtlAreLongPathsEnabled(), "expected long paths to be enabled\n" );
    peb->IsLongPathAwareProcess = old_value;
}

static void test_RtlComputeCrc32(void)
{
  DWORD crc = 0;

  crc = RtlComputeCrc32(crc, (const BYTE *)src, LEN);
  ok(crc == 0x40861dc2,"Expected 0x40861dc2, got %8lx\n", crc);
}


static void test_RtlFlushHeaps(void)
{
    static const char contents[] = "RtlFlushHeaps allocation";
    char *buffer;

    if (!pRtlFlushHeaps)
    {
        win_skip("RtlFlushHeaps is unavailable\n");
        return;
    }

    buffer = RtlAllocateHeap(GetProcessHeap(), 0, sizeof(contents));
    ok(!!buffer, "failed to allocate test buffer\n");
    if (!buffer) return;

    memcpy(buffer, contents, sizeof(contents));
    pRtlFlushHeaps();
    ok(!memcmp(buffer, contents, sizeof(contents)), "heap contents changed after flush\n");
    ok(RtlFreeHeap(GetProcessHeap(), 0, buffer), "failed to free test buffer\n");
}


typedef struct MY_HANDLE
{
    RTL_HANDLE RtlHandle;
    void * MyValue;
} MY_HANDLE;

static inline void RtlpMakeHandleAllocated(RTL_HANDLE * Handle)
{
    ULONG_PTR *AllocatedBit = (ULONG_PTR *)(&Handle->Next);
    *AllocatedBit = *AllocatedBit | 1;
}

static void test_HandleTables(void)
{
    BOOLEAN result;
    NTSTATUS status;
    ULONG Index;
    MY_HANDLE * MyHandle;
    RTL_HANDLE_TABLE HandleTable;

    RtlInitializeHandleTable(0x3FFF, sizeof(MY_HANDLE), &HandleTable);
    MyHandle = (MY_HANDLE *)RtlAllocateHandle(&HandleTable, &Index);
    ok(MyHandle != NULL, "RtlAllocateHandle failed\n");
    RtlpMakeHandleAllocated(&MyHandle->RtlHandle);
    MyHandle = NULL;
    result = RtlIsValidIndexHandle(&HandleTable, Index, (RTL_HANDLE **)&MyHandle);
    ok(result, "Handle %p wasn't valid\n", MyHandle);
    result = RtlFreeHandle(&HandleTable, &MyHandle->RtlHandle);
    ok(result, "Couldn't free handle %p\n", MyHandle);
    status = RtlDestroyHandleTable(&HandleTable);
    ok(status == STATUS_SUCCESS, "RtlDestroyHandleTable failed with error 0x%08lx\n", status);
}

static void test_RtlAllocateAndInitializeSid(void)
{
    static ULONG sub_authorities[SID_MAX_SUB_AUTHORITIES];
    NTSTATUS ret;
    SID_IDENTIFIER_AUTHORITY sia = {{ 1, 2, 3, 4, 5, 6 }};
    PSID psid;
    unsigned int i;

    ret = RtlAllocateAndInitializeSid(&sia, 0, 1, 2, 3, 4, 5, 6, 7, 8, &psid);
    ok(!ret, "RtlAllocateAndInitializeSid error %08lx\n", ret);
    ret = RtlFreeSid(psid);
    ok(!ret, "RtlFreeSid error %08lx\n", ret);

    /* these tests crash on XP */
    if (0)
    {
        RtlAllocateAndInitializeSid(NULL, 0, 1, 2, 3, 4, 5, 6, 7, 8, &psid);
        RtlAllocateAndInitializeSid(&sia, 0, 1, 2, 3, 4, 5, 6, 7, 8, NULL);
    }

    ret = RtlAllocateAndInitializeSid(&sia, 9, 1, 2, 3, 4, 5, 6, 7, 8, &psid);
    ok(ret == STATUS_INVALID_SID, "wrong error %08lx\n", ret);

    if (!pRtlAllocateAndInitializeSidEx)
    {
        win_skip("RtlAllocateAndInitializeSidEx is not available.\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(sub_authorities); ++i) sub_authorities[i] = 0x1000 + i;

    psid = (void *)0xdeadbeef;
    ret = pRtlAllocateAndInitializeSidEx(&sia, ARRAY_SIZE(sub_authorities),
                                         sub_authorities, &psid);
    ok(ret == STATUS_SUCCESS, "RtlAllocateAndInitializeSidEx error %08lx\n", ret);
    if (ret == STATUS_SUCCESS)
    {
        SID *allocated = psid;

        ok(allocated->Revision == SID_REVISION, "got revision %u\n", allocated->Revision);
        ok(allocated->SubAuthorityCount == ARRAY_SIZE(sub_authorities),
           "got sub-authority count %u\n", allocated->SubAuthorityCount);
        ok(!memcmp(&allocated->IdentifierAuthority, &sia, sizeof(sia)),
           "wrong identifier authority\n");
        ok(!memcmp(allocated->SubAuthority, sub_authorities, sizeof(sub_authorities)),
           "wrong sub-authorities\n");
        ret = RtlFreeSid(psid);
        ok(ret == STATUS_SUCCESS, "RtlFreeSid error %08lx\n", ret);
    }

    psid = (void *)0xdeadbeef;
    ret = pRtlAllocateAndInitializeSidEx(&sia, SID_MAX_SUB_AUTHORITIES + 1,
                                         sub_authorities, &psid);
    ok(ret == STATUS_INVALID_PARAMETER, "wrong error %08lx\n", ret);
    ok(psid == (void *)0xdeadbeef, "output changed to %p\n", psid);
}

static void test_RtlDeleteTimer(void)
{
    NTSTATUS ret;

    ret = RtlDeleteTimer(NULL, NULL, NULL);
    ok(ret == STATUS_INVALID_PARAMETER_1 ||
       ret == STATUS_INVALID_PARAMETER, /* W2K */
       "expected STATUS_INVALID_PARAMETER_1 or STATUS_INVALID_PARAMETER, got %lx\n", ret);
}

static void test_RtlThreadErrorMode(void)
{
    DWORD oldmode;
    BOOL is_wow64;
    DWORD mode;
    NTSTATUS status;

    if (!pRtlGetThreadErrorMode || !pRtlSetThreadErrorMode)
    {
        win_skip("RtlGetThreadErrorMode and/or RtlSetThreadErrorMode not available\n");
        return;
    }

    if (!pIsWow64Process || !pIsWow64Process(GetCurrentProcess(), &is_wow64))
        is_wow64 = FALSE;

    oldmode = pRtlGetThreadErrorMode();

    status = pRtlSetThreadErrorMode(0x70, &mode);
    ok(status == STATUS_SUCCESS ||
       status == STATUS_WAIT_1, /* Vista */
       "RtlSetThreadErrorMode failed with error 0x%08lx\n", status);
    ok(mode == oldmode,
       "RtlSetThreadErrorMode returned mode 0x%lx, expected 0x%lx\n",
       mode, oldmode);
    ok(pRtlGetThreadErrorMode() == 0x70,
       "RtlGetThreadErrorMode returned 0x%lx, expected 0x%x\n", mode, 0x70);
    if (!is_wow64)
    {
        ok(NtCurrentTeb()->HardErrorMode == 0x70,
           "The TEB contains 0x%lx, expected 0x%x\n",
           NtCurrentTeb()->HardErrorMode, 0x70);
    }

    status = pRtlSetThreadErrorMode(0, &mode);
    ok(status == STATUS_SUCCESS ||
       status == STATUS_WAIT_1, /* Vista */
       "RtlSetThreadErrorMode failed with error 0x%08lx\n", status);
    ok(mode == 0x70,
       "RtlSetThreadErrorMode returned mode 0x%lx, expected 0x%x\n",
       mode, 0x70);
    ok(pRtlGetThreadErrorMode() == 0,
       "RtlGetThreadErrorMode returned 0x%lx, expected 0x%x\n", mode, 0);
    if (!is_wow64)
    {
        ok(NtCurrentTeb()->HardErrorMode == 0,
           "The TEB contains 0x%lx, expected 0x%x\n",
           NtCurrentTeb()->HardErrorMode, 0);
    }

    for (mode = 1; mode; mode <<= 1)
    {
        status = pRtlSetThreadErrorMode(mode, NULL);
        if (mode & 0x70)
            ok(status == STATUS_SUCCESS ||
               status == STATUS_WAIT_1, /* Vista */
               "RtlSetThreadErrorMode(%lx,NULL) failed with error 0x%08lx\n",
               mode, status);
        else
            ok(status == STATUS_INVALID_PARAMETER_1,
               "RtlSetThreadErrorMode(%lx,NULL) returns 0x%08lx, "
               "expected STATUS_INVALID_PARAMETER_1\n",
               mode, status);
    }

    pRtlSetThreadErrorMode(oldmode, NULL);
}

static void test_LdrProcessRelocationBlock(void)
{
    IMAGE_BASE_RELOCATION *ret;
    USHORT reloc;
    DWORD addr32;
    SHORT addr16;

    addr32 = 0x50005;
    reloc = IMAGE_REL_BASED_HIGHLOW<<12;
    ret = LdrProcessRelocationBlock(&addr32, 1, &reloc, 0x500050);
    ok((USHORT*)ret == &reloc+1, "ret = %p, expected %p\n", ret, &reloc+1);
    ok(addr32 == 0x550055, "addr32 = %lx, expected 0x550055\n", addr32);

    addr16 = 0x505;
    reloc = IMAGE_REL_BASED_HIGH<<12;
    ret = LdrProcessRelocationBlock(&addr16, 1, &reloc, 0x500060);
    ok((USHORT*)ret == &reloc+1, "ret = %p, expected %p\n", ret, &reloc+1);
    ok(addr16 == 0x555, "addr16 = %x, expected 0x555\n", addr16);

    addr16 = 0x505;
    reloc = IMAGE_REL_BASED_LOW<<12;
    ret = LdrProcessRelocationBlock(&addr16, 1, &reloc, 0x500060);
    ok((USHORT*)ret == &reloc+1, "ret = %p, expected %p\n", ret, &reloc+1);
    ok(addr16 == 0x565, "addr16 = %x, expected 0x565\n", addr16);
}

static void test_RtlIpv4AddressToString(void)
{
    CHAR buffer[20];
    CHAR *res;
    IN_ADDR ip;
    DWORD_PTR len;

    ip.S_un.S_un_b.s_b1 = 1;
    ip.S_un.S_un_b.s_b2 = 2;
    ip.S_un.S_un_b.s_b3 = 3;
    ip.S_un.S_un_b.s_b4 = 4;

    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = RtlIpv4AddressToStringA(&ip, buffer);
    len = strlen(buffer);
    ok(res == (buffer + len), "got %p with '%s' (expected %p)\n", res, buffer, buffer + len);

    res = RtlIpv4AddressToStringA(&ip, NULL);
    ok( (res == (char *)~0) ||
        broken(res == (char *)len),        /* XP and w2003 */
        "got %p (expected ~0)\n", res);

    if (0) {
        /* this crashes in windows */
        memset(buffer, '#', sizeof(buffer) - 1);
        buffer[sizeof(buffer) -1] = 0;
        res = RtlIpv4AddressToStringA(NULL, buffer);
        trace("got %p with '%s'\n", res, buffer);
    }

    if (0) {
        /* this crashes in windows */
        res = RtlIpv4AddressToStringA(NULL, NULL);
        trace("got %p\n", res);
    }
}

static void test_RtlIpv4AddressToStringEx(void)
{
    CHAR ip_1234[] = "1.2.3.4";
    CHAR ip_1234_80[] = "1.2.3.4:80";
    LPSTR expect;
    CHAR buffer[30];
    NTSTATUS res;
    IN_ADDR ip;
    ULONG size;
    DWORD used;
    USHORT port;

    if (!pRtlIpv4AddressToStringExA)
    {
        win_skip("RtlIpv4AddressToStringExA not available\n");
        return;
    }

    ip.S_un.S_un_b.s_b1 = 1;
    ip.S_un.S_un_b.s_b2 = 2;
    ip.S_un.S_un_b.s_b3 = 3;
    ip.S_un.S_un_b.s_b4 = 4;

    port = htons(80);
    expect = ip_1234_80;

    size = sizeof(buffer);
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    used = strlen(buffer);
    ok( (res == STATUS_SUCCESS) &&
        (size == strlen(expect) + 1) && !strcmp(buffer, expect),
        "got 0x%lx and size %ld with '%s'\n", res, size, buffer);

    size = used + 1;
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    ok( (res == STATUS_SUCCESS) &&
        (size == strlen(expect) + 1) && !strcmp(buffer, expect),
        "got 0x%lx and size %ld with '%s'\n", res, size, buffer);

    size = used;
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    ok( (res == STATUS_INVALID_PARAMETER) && (size == used + 1),
        "got 0x%lx and %ld with '%s' (expected STATUS_INVALID_PARAMETER and %ld)\n",
        res, size, buffer, used + 1);

    size = used - 1;
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    ok( (res == STATUS_INVALID_PARAMETER) && (size == used + 1),
        "got 0x%lx and %ld with '%s' (expected STATUS_INVALID_PARAMETER and %ld)\n",
        res, size, buffer, used + 1);


    /* to get only the ip, use 0 as port */
    port = 0;
    expect = ip_1234;

    size = sizeof(buffer);
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    used = strlen(buffer);
    ok( (res == STATUS_SUCCESS) &&
        (size == strlen(expect) + 1) && !strcmp(buffer, expect),
        "got 0x%lx and size %ld with '%s'\n", res, size, buffer);

    size = used + 1;
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    ok( (res == STATUS_SUCCESS) &&
        (size == strlen(expect) + 1) && !strcmp(buffer, expect),
        "got 0x%lx and size %ld with '%s'\n", res, size, buffer);

    size = used;
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    ok( (res == STATUS_INVALID_PARAMETER) && (size == used + 1),
        "got 0x%lx and %ld with '%s' (expected STATUS_INVALID_PARAMETER and %ld)\n",
        res, size, buffer, used + 1);

    size = used - 1;
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, port, buffer, &size);
    ok( (res == STATUS_INVALID_PARAMETER) && (size == used + 1),
        "got 0x%lx and %ld with '%s' (expected STATUS_INVALID_PARAMETER and %ld)\n",
        res, size, buffer, used + 1);


    /* parameters are checked */
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(&ip, 0, buffer, NULL);
    ok(res == STATUS_INVALID_PARAMETER,
        "got 0x%lx with '%s' (expected STATUS_INVALID_PARAMETER)\n", res, buffer);

    size = sizeof(buffer);
    res = pRtlIpv4AddressToStringExA(&ip, 0, NULL, &size);
    ok( res == STATUS_INVALID_PARAMETER,
        "got 0x%lx and size %ld (expected STATUS_INVALID_PARAMETER)\n", res, size);

    size = sizeof(buffer);
    memset(buffer, '#', sizeof(buffer) - 1);
    buffer[sizeof(buffer) -1] = 0;
    res = pRtlIpv4AddressToStringExA(NULL, 0, buffer, &size);
    ok( res == STATUS_INVALID_PARAMETER,
        "got 0x%lx and size %ld with '%s' (expected STATUS_INVALID_PARAMETER)\n",
        res, size, buffer);
}

static struct
{
    PCSTR address;
    NTSTATUS res;
    int terminator_offset;
    int ip[4];
    enum { normal_4, strict_diff_4 = 1, ex_fail_4 = 2 } flags;
    NTSTATUS res_strict;
    int terminator_offset_strict;
    int ip_strict[4];
} ipv4_tests[] =
{
    { "",                       STATUS_INVALID_PARAMETER,  0, { -1 } },
    { " ",                      STATUS_INVALID_PARAMETER,  0, { -1 } },
    { "1.1.1.1",                STATUS_SUCCESS,            7, {   1,   1,   1,   1 } },
    { "0.0.0.0",                STATUS_SUCCESS,            7, {   0,   0,   0,   0 } },
    { "255.255.255.255",        STATUS_SUCCESS,           15, { 255, 255, 255, 255 } },
    { "255.255.255.255:123",    STATUS_SUCCESS,           15, { 255, 255, 255, 255 } },
    { "255.255.255.256",        STATUS_INVALID_PARAMETER, 15, { -1 } },
    { "255.255.255.4294967295", STATUS_INVALID_PARAMETER, 22, { -1 } },
    { "255.255.255.4294967296", STATUS_INVALID_PARAMETER, 21, { -1 } },
    { "255.255.255.4294967297", STATUS_INVALID_PARAMETER, 21, { -1 } },
    { "a",                      STATUS_INVALID_PARAMETER,  0, { -1 } },
    { "1.1.1.0xaA",             STATUS_SUCCESS,           10, {   1,   1,   1, 170 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "1.1.1.0XaA",             STATUS_SUCCESS,           10, {   1,   1,   1, 170 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "1.1.1.0x",               STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "1.1.1.0xff",             STATUS_SUCCESS,           10, {   1,   1,   1, 255 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "1.1.1.0x100",            STATUS_INVALID_PARAMETER, 11, { -1 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "1.1.1.0xffffffff",       STATUS_INVALID_PARAMETER, 16, { -1 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "1.1.1.0x100000000",      STATUS_INVALID_PARAMETER, 16, { -1, 0, 0, 0 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "1.1.1.010",              STATUS_SUCCESS,            9, {   1,   1,   1,   8 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "1.1.1.00",               STATUS_SUCCESS,            8, {   1,   1,   1,   0 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "1.1.1.007",              STATUS_SUCCESS,            9, {   1,   1,   1,   7 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "1.1.1.08",               STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "1.1.1.008",              STATUS_SUCCESS,            8, {   1,   1,   1,   0 }, strict_diff_4 | ex_fail_4,
                                STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "1.1.1.0a",               STATUS_SUCCESS,            7, {   1,   1,   1,   0 }, ex_fail_4 },
    { "1.1.1.0o10",             STATUS_SUCCESS,            7, {   1,   1,   1,   0 }, ex_fail_4 },
    { "1.1.1.0b10",             STATUS_SUCCESS,            7, {   1,   1,   1,   0 }, ex_fail_4 },
    { "1.1.1.-2",               STATUS_INVALID_PARAMETER,  6, { -1 } },
    { "1",                      STATUS_SUCCESS,            1, {   0,   0,   0,   1 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  1, { -1 } },
    { "-1",                     STATUS_INVALID_PARAMETER,  0, { -1 } },
    { "1.2",                    STATUS_SUCCESS,            3, {   1,   0,   0,   2 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  3, { -1 } },
    { "1000.2000",              STATUS_INVALID_PARAMETER,  9, { -1 } },
    { "1.2.",                   STATUS_INVALID_PARAMETER,  4, { -1 } },
    { "1..2",                   STATUS_INVALID_PARAMETER,  3, { -1 } },
    { "1...2",                  STATUS_INVALID_PARAMETER,  3, { -1 } },
    { "1.2.3",                  STATUS_SUCCESS,            5, {   1,   2,   0,   3 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  5, { -1 } },
    { "1.2.3.",                 STATUS_INVALID_PARAMETER,  6, { -1 } },
    { "203569230",              STATUS_SUCCESS,            9, {  12,  34,  56,  78 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  9, { -1 } },
    { "1.223756",               STATUS_SUCCESS,            8, {   1,   3, 106,  12 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  8, { -1 } },
    { "3.4.756",                STATUS_SUCCESS,            7, {   3,   4,   2, 244 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "756.3.4",                STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "3.756.4",                STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "3.4.756.1",              STATUS_INVALID_PARAMETER,  9, { -1 } },
    { "3.4.65536",              STATUS_INVALID_PARAMETER,  9, { -1 } },
    { "3.4.5.6.7",              STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "3.4.5.+6",               STATUS_INVALID_PARAMETER,  6, { -1 } },
    { " 3.4.5.6",               STATUS_INVALID_PARAMETER,  0, { -1 } },
    { "\t3.4.5.6",              STATUS_INVALID_PARAMETER,  0, { -1 } },
    { "3.4.5.6 ",               STATUS_SUCCESS,            7, {   3,   4,   5,   6 }, ex_fail_4 },
    { "3. 4.5.6",               STATUS_INVALID_PARAMETER,  2, { -1 } },
    { ".",                      STATUS_INVALID_PARAMETER,  1, { -1 } },
    { "..",                     STATUS_INVALID_PARAMETER,  1, { -1 } },
    { "1.",                     STATUS_INVALID_PARAMETER,  2, { -1 } },
    { "1..",                    STATUS_INVALID_PARAMETER,  3, { -1 } },
    { ".1",                     STATUS_INVALID_PARAMETER,  1, { -1 } },
    { ".1.",                    STATUS_INVALID_PARAMETER,  1, { -1 } },
    { ".1.2.3",                 STATUS_INVALID_PARAMETER,  1, { -1 } },
    { ".1.2.3.4",               STATUS_INVALID_PARAMETER,  1, { -1 } },
    { "0.1.2.3",                STATUS_SUCCESS,            7, {   0,   1,   2,   3 } },
    { "0.1.2.3.",               STATUS_INVALID_PARAMETER,  7, { -1 } },
    { "[0.1.2.3]",              STATUS_INVALID_PARAMETER,  0, { -1 } },
    { "0x00010203",             STATUS_SUCCESS,           10, {   0,   1,   2,   3 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  2, { -1 } },
    { "0X00010203",             STATUS_SUCCESS,           10, {   0,   1,   2,   3 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  2, { -1 } },
    { "0x1234",                 STATUS_SUCCESS,            6, {   0,   0,  18,  52 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  2, { -1 } },
    { "0x123456789",            STATUS_SUCCESS,           11, {  35,  69, 103, 137 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  2, { -1 } },
    { "0x00010Q03",             STATUS_SUCCESS,            7, {   0,   0,   0,  16 }, strict_diff_4 | ex_fail_4,
                                STATUS_INVALID_PARAMETER,  2, { -1 } },
    { "x00010203",              STATUS_INVALID_PARAMETER,  0, { -1 } },
    { "1234BEEF",               STATUS_SUCCESS,            4, {   0,   0,   4, 210 }, strict_diff_4 | ex_fail_4,
                                STATUS_INVALID_PARAMETER,  4, { -1 } },
    { "017700000001",           STATUS_SUCCESS,           12, { 127,   0,   0,   1 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  1, { -1 } },
    { "0777",                   STATUS_SUCCESS,            4, {   0,   0,   1, 255 }, strict_diff_4,
                                STATUS_INVALID_PARAMETER,  1, { -1 } },
    { "::1",                    STATUS_INVALID_PARAMETER,  0, { -1 } },
    { ":1",                     STATUS_INVALID_PARAMETER,  0, { -1 } },
};

static void init_ip4(IN_ADDR* addr, const int src[4])
{
    if (!src || src[0] == -1)
    {
        addr->S_un.S_addr = 0xabababab;
    }
    else
    {
        addr->S_un.S_un_b.s_b1 = src[0];
        addr->S_un.S_un_b.s_b2 = src[1];
        addr->S_un.S_un_b.s_b3 = src[2];
        addr->S_un.S_un_b.s_b4 = src[3];
    }
}

static void test_RtlIpv4StringToAddress(void)
{
    NTSTATUS res;
    IN_ADDR ip, expected_ip;
    PCSTR terminator;
    CHAR dummy;
    int i;

    if (0)
    {
        /* leaving either parameter NULL crashes on Windows */
        res = RtlIpv4StringToAddressA(NULL, FALSE, &terminator, &ip);
        res = RtlIpv4StringToAddressA("1.1.1.1", FALSE, NULL, &ip);
        res = RtlIpv4StringToAddressA("1.1.1.1", FALSE, &terminator, NULL);
        /* same for the wide char version */
        /*
        res = RtlIpv4StringToAddressW(NULL, FALSE, &terminatorW, &ip);
        res = RtlIpv4StringToAddressW(L"1.1.1.1", FALSE, NULL, &ip);
        res = RtlIpv4StringToAddressW(L"1.1.1.1", FALSE, &terminatorW, NULL);
        */
    }

    for (i = 0; i < ARRAY_SIZE(ipv4_tests); i++)
    {
        /* non-strict */
        terminator = &dummy;
        ip.S_un.S_addr = 0xabababab;
        res = RtlIpv4StringToAddressA(ipv4_tests[i].address, FALSE, &terminator, &ip);
        ok(res == ipv4_tests[i].res,
           "[%s] res = 0x%08lx, expected 0x%08lx\n",
           ipv4_tests[i].address, res, ipv4_tests[i].res);
        ok(terminator == ipv4_tests[i].address + ipv4_tests[i].terminator_offset,
           "[%s] terminator = %p, expected %p\n",
           ipv4_tests[i].address, terminator, ipv4_tests[i].address + ipv4_tests[i].terminator_offset);

        init_ip4(&expected_ip, ipv4_tests[i].ip);
        ok(ip.S_un.S_addr == expected_ip.S_un.S_addr,
           "[%s] ip = %08lx, expected %08lx\n",
           ipv4_tests[i].address, ip.S_un.S_addr, expected_ip.S_un.S_addr);

        if (!(ipv4_tests[i].flags & strict_diff_4))
        {
            ipv4_tests[i].res_strict = ipv4_tests[i].res;
            ipv4_tests[i].terminator_offset_strict = ipv4_tests[i].terminator_offset;
            ipv4_tests[i].ip_strict[0] = ipv4_tests[i].ip[0];
            ipv4_tests[i].ip_strict[1] = ipv4_tests[i].ip[1];
            ipv4_tests[i].ip_strict[2] = ipv4_tests[i].ip[2];
            ipv4_tests[i].ip_strict[3] = ipv4_tests[i].ip[3];
        }
        /* strict */
        terminator = &dummy;
        ip.S_un.S_addr = 0xabababab;
        res = RtlIpv4StringToAddressA(ipv4_tests[i].address, TRUE, &terminator, &ip);
        ok(res == ipv4_tests[i].res_strict,
           "[%s] res = 0x%08lx, expected 0x%08lx\n",
           ipv4_tests[i].address, res, ipv4_tests[i].res_strict);
        ok(terminator == ipv4_tests[i].address + ipv4_tests[i].terminator_offset_strict,
           "[%s] terminator = %p, expected %p\n",
           ipv4_tests[i].address, terminator, ipv4_tests[i].address + ipv4_tests[i].terminator_offset_strict);

        init_ip4(&expected_ip, ipv4_tests[i].ip_strict);
        ok(ip.S_un.S_addr == expected_ip.S_un.S_addr,
           "[%s] ip = %08lx, expected %08lx\n",
           ipv4_tests[i].address, ip.S_un.S_addr, expected_ip.S_un.S_addr);
    }
}

static void test_RtlIpv4StringToAddressEx(void)
{
    NTSTATUS res;
    IN_ADDR ip, expected_ip;
    USHORT port;
    static const struct
    {
        PCSTR address;
        NTSTATUS res;
        int ip[4];
        USHORT port;
    } ipv4_ex_tests[] =
    {
        { "",               STATUS_INVALID_PARAMETER,   { -1 },         0xdead },
        { " ",              STATUS_INVALID_PARAMETER,   { -1 },         0xdead },
        { "1.1.1.1:",       STATUS_INVALID_PARAMETER,   { 1, 1, 1, 1 }, 0xdead },
        { "1.1.1.1+",       STATUS_INVALID_PARAMETER,   { 1, 1, 1, 1 }, 0xdead },
        { "1.1.1.1:1",      STATUS_SUCCESS,             { 1, 1, 1, 1 }, 0x100 },
        { "256.1.1.1:1",    STATUS_INVALID_PARAMETER,   { -1 },         0xdead },
        { "-1.1.1.1:1",     STATUS_INVALID_PARAMETER,   { -1 },         0xdead },
        { "0.0.0.0:0",      STATUS_INVALID_PARAMETER,   { 0, 0, 0, 0 }, 0xdead },
        { "0.0.0.0:1",      STATUS_SUCCESS,             { 0, 0, 0, 0 }, 0x100 },
        { "1.2.3.4:65535",  STATUS_SUCCESS,             { 1, 2, 3, 4 }, 65535 },
        { "1.2.3.4:65536",  STATUS_INVALID_PARAMETER,   { 1, 2, 3, 4 }, 0xdead },
        { "1.2.3.4:0xffff", STATUS_SUCCESS,             { 1, 2, 3, 4 }, 65535 },
        { "1.2.3.4:0XfFfF", STATUS_SUCCESS,             { 1, 2, 3, 4 }, 65535 },
        { "1.2.3.4:011064", STATUS_SUCCESS,             { 1, 2, 3, 4 }, 0x3412 },
        { "1.2.3.4:1234a",  STATUS_INVALID_PARAMETER,   { 1, 2, 3, 4 }, 0xdead },
        { "1.2.3.4:1234+",  STATUS_INVALID_PARAMETER,   { 1, 2, 3, 4 }, 0xdead },
        { "1.2.3.4: 1234",  STATUS_INVALID_PARAMETER,   { 1, 2, 3, 4 }, 0xdead },
        { "1.2.3.4:\t1234", STATUS_INVALID_PARAMETER,   { 1, 2, 3, 4 }, 0xdead },
    };
    unsigned int i;
    BOOLEAN strict;

    if (!pRtlIpv4StringToAddressExA)
    {
        win_skip("RtlIpv4StringToAddressEx not available\n");
        return;
    }

    /* do not crash, and do not touch the ip / port. */
    ip.S_un.S_addr = 0xabababab;
    port = 0xdead;
    res = pRtlIpv4StringToAddressExA(NULL, FALSE, &ip, &port);
    ok(res == STATUS_INVALID_PARAMETER, "[null address] res = 0x%08lx, expected 0x%08lx\n",
       res, STATUS_INVALID_PARAMETER);
    ok(ip.S_un.S_addr == 0xabababab, "RtlIpv4StringToAddressExA should not touch the ip!, ip == %lx\n", ip.S_un.S_addr);
    ok(port == 0xdead, "RtlIpv4StringToAddressExA should not touch the port!, port == %x\n", port);

    port = 0xdead;
    res = pRtlIpv4StringToAddressExA("1.1.1.1", FALSE, NULL, &port);
    ok(res == STATUS_INVALID_PARAMETER, "[null ip] res = 0x%08lx, expected 0x%08lx\n",
       res, STATUS_INVALID_PARAMETER);
    ok(port == 0xdead, "RtlIpv4StringToAddressExA should not touch the port!, port == %x\n", port);

    ip.S_un.S_addr = 0xabababab;
    port = 0xdead;
    res = pRtlIpv4StringToAddressExA("1.1.1.1", FALSE, &ip, NULL);
    ok(res == STATUS_INVALID_PARAMETER, "[null port] res = 0x%08lx, expected 0x%08lx\n",
       res, STATUS_INVALID_PARAMETER);
    ok(ip.S_un.S_addr == 0xabababab, "RtlIpv4StringToAddressExA should not touch the ip!, ip == %lx\n", ip.S_un.S_addr);
    ok(port == 0xdead, "RtlIpv4StringToAddressExA should not touch the port!, port == %x\n", port);

    /* first we run the non-ex testcases on the ex function */
    for (i = 0; i < ARRAY_SIZE(ipv4_tests); i++)
    {
        NTSTATUS expect_res = (ipv4_tests[i].flags & ex_fail_4) ? STATUS_INVALID_PARAMETER : ipv4_tests[i].res;

        /* non-strict */
        port = 0xdead;
        ip.S_un.S_addr = 0xabababab;
        res = pRtlIpv4StringToAddressExA(ipv4_tests[i].address, FALSE, &ip, &port);
        ok(res == expect_res, "[%s] res = 0x%08lx, expected 0x%08lx\n",
           ipv4_tests[i].address, res, expect_res);

        init_ip4(&expected_ip, ipv4_tests[i].ip);
        ok(ip.S_un.S_addr == expected_ip.S_un.S_addr, "[%s] ip = %08lx, expected %08lx\n",
           ipv4_tests[i].address, ip.S_un.S_addr, expected_ip.S_un.S_addr);

        if (!(ipv4_tests[i].flags & strict_diff_4))
        {
            ipv4_tests[i].res_strict = ipv4_tests[i].res;
            ipv4_tests[i].terminator_offset_strict = ipv4_tests[i].terminator_offset;
            ipv4_tests[i].ip_strict[0] = ipv4_tests[i].ip[0];
            ipv4_tests[i].ip_strict[1] = ipv4_tests[i].ip[1];
            ipv4_tests[i].ip_strict[2] = ipv4_tests[i].ip[2];
            ipv4_tests[i].ip_strict[3] = ipv4_tests[i].ip[3];
        }
        /* strict */
        expect_res = (ipv4_tests[i].flags & ex_fail_4) ? STATUS_INVALID_PARAMETER : ipv4_tests[i].res_strict;
        port = 0xdead;
        ip.S_un.S_addr = 0xabababab;
        res = pRtlIpv4StringToAddressExA(ipv4_tests[i].address, TRUE, &ip, &port);
        ok(res == expect_res, "[%s] res = 0x%08lx, expected 0x%08lx\n",
           ipv4_tests[i].address, res, expect_res);

        init_ip4(&expected_ip, ipv4_tests[i].ip_strict);
        ok(ip.S_un.S_addr == expected_ip.S_un.S_addr, "[%s] ip = %08lx, expected %08lx\n",
           ipv4_tests[i].address, ip.S_un.S_addr, expected_ip.S_un.S_addr);
    }


    for (i = 0; i < ARRAY_SIZE(ipv4_ex_tests); i++)
    {
        /* Strict is only relevant for the ip address, so make sure that it does not influence the port */
        for (strict = 0; strict < 2; strict++)
        {
            ip.S_un.S_addr = 0xabababab;
            port = 0xdead;
            res = pRtlIpv4StringToAddressExA(ipv4_ex_tests[i].address, strict, &ip, &port);
            ok(res == ipv4_ex_tests[i].res, "[%s] res = 0x%08lx, expected 0x%08lx\n",
               ipv4_ex_tests[i].address, res, ipv4_ex_tests[i].res);

            init_ip4(&expected_ip, ipv4_ex_tests[i].ip);
            ok(ip.S_un.S_addr == expected_ip.S_un.S_addr, "[%s] ip = %08lx, expected %08lx\n",
               ipv4_ex_tests[i].address, ip.S_un.S_addr, expected_ip.S_un.S_addr);
            ok(port == ipv4_ex_tests[i].port, "[%s] port = %u, expected %u\n",
               ipv4_ex_tests[i].address, port, ipv4_ex_tests[i].port);
        }
    }
}

/* ipv6 addresses based on the set from https://github.com/beaugunderson/javascript-ipv6/tree/master/test/data */
static const struct
{
    PCSTR address;
    NTSTATUS res;
    int terminator_offset;
    int ip[8];
    /* win_broken: XP and Vista do not handle this correctly
        ex_fail: Ex function does need the string to be terminated, non-Ex does not.
        ex_skip: test doesn't make sense for Ex (f.e. it's invalid for non-Ex but valid for Ex) */
    enum { normal_6, win_broken_6 = 1, ex_fail_6 = 2, ex_skip_6 = 4, win_extra_zero = 8 } flags;
} ipv6_tests[] =
{
    { "0000:0000:0000:0000:0000:0000:0000:0000",        STATUS_SUCCESS,             39,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "0000:0000:0000:0000:0000:0000:0000:0001",        STATUS_SUCCESS,             39,
            { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
    { "0:0:0:0:0:0:0:0",                                STATUS_SUCCESS,             15,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "0:0:0:0:0:0:0:1",                                STATUS_SUCCESS,             15,
            { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
    { "0:0:0:0:0:0:0::",                                STATUS_SUCCESS,             15,
            { 0, 0, 0, 0, 0, 0, 0, 0 }, win_broken_6 },
    { "0:0:0:0:0:0:13.1.68.3",                          STATUS_SUCCESS,             21,
            { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },
    { "0:0:0:0:0:0::",                                  STATUS_SUCCESS,             13,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "0:0:0:0:0::",                                    STATUS_SUCCESS,             11,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "0:0:0:0:0:FFFF:129.144.52.38",                   STATUS_SUCCESS,             28,
            { 0, 0, 0, 0, 0, 0xffff, 0x9081, 0x2634 } },
    { "0::",                                            STATUS_SUCCESS,             3,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "0:1:2:3:4:5:6:7",                                STATUS_SUCCESS,             15,
            { 0, 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700 } },
    { "1080:0:0:0:8:800:200c:417a",                     STATUS_SUCCESS,             26,
            { 0x8010, 0, 0, 0, 0x800, 0x8, 0x0c20, 0x7a41 } },
    { "0:a:b:c:d:e:f::",                                STATUS_SUCCESS,             15,
            { 0, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00, 0xf00, 0 }, win_broken_6 },
    { "1111:2222:3333:4444:5555:6666:123.123.123.123",  STATUS_SUCCESS,             45,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
    { "1111:2222:3333:4444:5555:6666:7777:8888",        STATUS_SUCCESS,             39,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 } },
    { "1111:2222:3333:4444:0x5555:6666:7777:8888",      STATUS_INVALID_PARAMETER,   21,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:x555:6666:7777:8888",        STATUS_INVALID_PARAMETER,   20,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:0r5555:6666:7777:8888",      STATUS_INVALID_PARAMETER,   21,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:r5555:6666:7777:8888",       STATUS_INVALID_PARAMETER,   20,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:5555:6666:7777::",           STATUS_SUCCESS,             36,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0 }, win_broken_6 },
    { "1111:2222:3333:4444:5555:6666::",                STATUS_SUCCESS,             31,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0 } },
    { "1111:2222:3333:4444:5555:6666::8888",            STATUS_SUCCESS,             35,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0x8888 } },
    { "1111:2222:3333:4444:5555:6666::7777:8888",       STATUS_SUCCESS,             35,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0x7777 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777::8888",       STATUS_SUCCESS,             36,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0 }, ex_fail_6|win_broken_6 },
    { "1111:2222:3333:4444:5555::",                     STATUS_SUCCESS,             26,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0 } },
    { "1111:2222:3333:4444:5555::123.123.123.123",      STATUS_SUCCESS,             41,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0x7b7b, 0x7b7b } },
    { "1111:2222:3333:4444:5555::0x1.123.123.123",      STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0x100 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555::0x88",                 STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0x8800 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555::0X88",                 STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0x8800 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555::0X",                   STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555::0X88:7777",            STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0x8800 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555::0x8888",               STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0x8888 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555::0x80000000",           STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0xffff }, ex_fail_6 },
    { "1111:2222:3333:4444::5555:0x012345678",          STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0, 0x5555, 0x7856 }, ex_fail_6 },
    { "1111:2222:3333:4444::5555:0x123456789",          STATUS_SUCCESS,             27,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0, 0x5555, 0xffff }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:0x12345678",       STATUS_INVALID_PARAMETER,   31,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0xabab, 0xabab }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777:0x80000000", STATUS_SUCCESS,             36,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0xffff }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777:0x012345678", STATUS_SUCCESS,             36,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x7856 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777:0x123456789", STATUS_SUCCESS,             36,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0xffff }, ex_fail_6 },
    { "111:222:333:444:555:666:777:0x123456789abcdef0", STATUS_SUCCESS,             29,
            { 0x1101, 0x2202, 0x3303, 0x4404, 0x5505, 0x6606, 0x7707, 0xffff }, ex_fail_6 },
    { "1111:2222:3333:4444:5555::08888",                STATUS_INVALID_PARAMETER,   31,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:5555::08888::",              STATUS_INVALID_PARAMETER,   31,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:5555:6666:7777:fffff:",      STATUS_INVALID_PARAMETER,   40,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0xabab } },
    { "1111:2222:3333:4444:5555:6666::fffff:",          STATUS_INVALID_PARAMETER,   36,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:5555::fffff",                STATUS_INVALID_PARAMETER,   31,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444::fffff",                     STATUS_INVALID_PARAMETER,   26,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333::fffff",                          STATUS_INVALID_PARAMETER,   21,
            { 0x1111, 0x2222, 0x3333, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:5555::7777:8888",            STATUS_SUCCESS,             35,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0x7777, 0x8888 } },
    { "1111:2222:3333:4444:5555::8888",                 STATUS_SUCCESS,             30,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0x8888 } },
    { "1111::",                                         STATUS_SUCCESS,             6,
            { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },
    { "1111::123.123.123.123",                          STATUS_SUCCESS,             21,
            { 0x1111, 0, 0, 0, 0, 0, 0x7b7b, 0x7b7b } },
    { "1111::3333:4444:5555:6666:123.123.123.123",      STATUS_SUCCESS,             41,
            { 0x1111, 0, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
    { "1111::3333:4444:5555:6666:7777:8888",            STATUS_SUCCESS,             35,
            { 0x1111, 0, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 } },
    { "1111::4444:5555:6666:123.123.123.123",           STATUS_SUCCESS,             36,
            { 0x1111, 0, 0, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
    { "1111::4444:5555:6666:7777:8888",                 STATUS_SUCCESS,             30,
            { 0x1111, 0, 0, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 } },
    { "1111::5555:6666:123.123.123.123",                STATUS_SUCCESS,             31,
            { 0x1111, 0, 0, 0, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
    { "1111::5555:6666:7777:8888",                      STATUS_SUCCESS,             25,
            { 0x1111, 0, 0, 0, 0x5555, 0x6666, 0x7777, 0x8888 } },
    { "1111::6666:123.123.123.123",                     STATUS_SUCCESS,             26,
            { 0x1111, 0, 0, 0, 0, 0x6666, 0x7b7b, 0x7b7b } },
    { "1111::6666:7777:8888",                           STATUS_SUCCESS,             20,
            { 0x1111, 0, 0, 0, 0, 0x6666, 0x7777, 0x8888 } },
    { "1111::7777:8888",                                STATUS_SUCCESS,             15,
            { 0x1111, 0, 0, 0, 0, 0, 0x7777, 0x8888 } },
    { "1111::8888",                                     STATUS_SUCCESS,             10,
            { 0x1111, 0, 0, 0, 0, 0, 0, 0x8888 } },
    { "1:2:3:4:5:6:1.2.3.4",                            STATUS_SUCCESS,             19,
            { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x201, 0x403 } },
    { "1:2:3:4:5:6:7:8",                                STATUS_SUCCESS,             15,
            { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800 } },
    { "1:2:3:4:5:6::",                                  STATUS_SUCCESS,             13,
            { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0, 0 } },
    { "1:2:3:4:5:6::8",                                 STATUS_SUCCESS,             14,
            { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0, 0x800 } },
    { "2001:0000:1234:0000:0000:C1C0:ABCD:0876",        STATUS_SUCCESS,             39,
            { 0x120, 0, 0x3412, 0, 0, 0xc0c1, 0xcdab, 0x7608 } },
    { "2001:0000:4136:e378:8000:63bf:3fff:fdd2",        STATUS_SUCCESS,             39,
            { 0x120, 0, 0x3641, 0x78e3, 0x80, 0xbf63, 0xff3f, 0xd2fd } },
    { "2001:0db8:0:0:0:0:1428:57ab",                    STATUS_SUCCESS,             27,
            { 0x120, 0xb80d, 0, 0, 0, 0, 0x2814, 0xab57 } },
    { "2001:0db8:1234:ffff:ffff:ffff:ffff:ffff",        STATUS_SUCCESS,             39,
            { 0x120, 0xb80d, 0x3412, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff } },
    { "2001::CE49:7601:2CAD:DFFF:7C94:FFFE",            STATUS_SUCCESS,             35,
            { 0x120, 0, 0x49ce, 0x176, 0xad2c, 0xffdf, 0x947c, 0xfeff } },
    { "2001:db8:85a3::8a2e:370:7334",                   STATUS_SUCCESS,             28,
            { 0x120, 0xb80d, 0xa385, 0, 0, 0x2e8a, 0x7003, 0x3473 } },
    { "3ffe:0b00:0000:0000:0001:0000:0000:000a",        STATUS_SUCCESS,             39,
            { 0xfe3f, 0xb, 0, 0, 0x100, 0, 0, 0xa00 } },
    { "::",                                             STATUS_SUCCESS,             2,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "::%16",                                          STATUS_SUCCESS,             2,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "::/16",                                          STATUS_SUCCESS,             2,
            { 0, 0, 0, 0, 0, 0, 0, 0 }, ex_fail_6 },
    { "::01234",                                        STATUS_INVALID_PARAMETER,   7,
            { 0, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "::0",                                            STATUS_SUCCESS,             3,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "::0:0",                                          STATUS_SUCCESS,             5,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "::0:0:0",                                        STATUS_SUCCESS,             7,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "::0:0:0:0",                                      STATUS_SUCCESS,             9,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "::0:0:0:0:0",                                    STATUS_SUCCESS,             11,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    { "::0:0:0:0:0:0",                                  STATUS_SUCCESS,             13,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
    /* this one and the next one are incorrectly parsed before Windows 11,
        it adds one zero too many in front, cutting off the last digit. */
    { "::0:0:0:0:0:0:0",                                STATUS_SUCCESS,             15,
            { 0, 0, 0, 0, 0, 0, 0, 0 }, win_broken_6|win_extra_zero },
    { "::0:a:b:c:d:e:f",                                STATUS_SUCCESS,             15,
            { 0, 0, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00, 0xf00 }, win_broken_6|win_extra_zero },
    { "::123.123.123.123",                              STATUS_SUCCESS,             17,
            { 0, 0, 0, 0, 0, 0, 0x7b7b, 0x7b7b } },
    { "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",        STATUS_SUCCESS,             39,
            { 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff } },

    { "':10.0.0.1",                                     STATUS_INVALID_PARAMETER,   0,
            { -1 } },
    { "-1",                                             STATUS_INVALID_PARAMETER,   0,
            { -1 } },
    { "02001:0000:1234:0000:0000:C1C0:ABCD:0876",       STATUS_INVALID_PARAMETER,   -1,
            { -1 } },
    { "2001:00000:1234:0000:0000:C1C0:ABCD:0876",       STATUS_INVALID_PARAMETER,   -1,
            { 0x120, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "2001:0000:01234:0000:0000:C1C0:ABCD:0876",       STATUS_INVALID_PARAMETER,   -1,
            { 0x120, 0, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "2001:0000::01234.0",                             STATUS_INVALID_PARAMETER,   -1,
            { 0x120, 0, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "2001:0::b.0",                                    STATUS_SUCCESS,             9,
            { 0x120, 0, 0, 0, 0, 0, 0, 0xb00 }, ex_fail_6 },
    { "2001::0:b.0",                                    STATUS_SUCCESS,             9,
            { 0x120, 0, 0, 0, 0, 0, 0, 0xb00 }, ex_fail_6 },
    { "1.2.3.4",                                        STATUS_INVALID_PARAMETER,   7,
            { 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1.2.3.4:1111::5555",                             STATUS_INVALID_PARAMETER,   7,
            { 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1.2.3.4::5555",                                  STATUS_INVALID_PARAMETER,   7,
            { 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "11112222:3333:4444:5555:6666:1.2.3.4",           STATUS_INVALID_PARAMETER,   -1,
            { -1 } },
    { "11112222:3333:4444:5555:6666:7777:8888",         STATUS_INVALID_PARAMETER,   -1,
            { -1 } },
    { "1111",                                           STATUS_INVALID_PARAMETER,   4,
            { -1 } },
    { "0x1111",                                         STATUS_INVALID_PARAMETER,   1,
            { -1 } },
    { "1111:22223333:4444:5555:6666:1.2.3.4",           STATUS_INVALID_PARAMETER,   -1,
            { 0x1111, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:22223333:4444:5555:6666:7777:8888",         STATUS_INVALID_PARAMETER,   -1,
            { 0x1111, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:123456789:4444:5555:6666:7777:8888",        STATUS_INVALID_PARAMETER,   -1,
            { 0x1111, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:1234567890abcdef0:4444:5555:6666:7777:888", STATUS_INVALID_PARAMETER,   -1,
            { 0x1111, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:",                                     STATUS_INVALID_PARAMETER,   10,
            { 0x1111, 0x2222, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:1.2.3.4",                              STATUS_INVALID_PARAMETER,   17,
            { 0x1111, 0x2222, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333",                                 STATUS_INVALID_PARAMETER,   14,
            { 0x1111, 0x2222, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111:2222:3333:4444:5555:6666::1.2.3.4",         STATUS_SUCCESS,             32,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0x100 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777:1.2.3.4",     STATUS_SUCCESS,             36,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x100 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777:8888:",       STATUS_SUCCESS,             39,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777:8888:1.2.3.4",STATUS_SUCCESS,             39,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 }, ex_fail_6 },
    { "1111:2222:3333:4444:5555:6666:7777:8888:9999",   STATUS_SUCCESS,             39,
            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 }, ex_fail_6 },
    { "1111:2222:::",                                   STATUS_SUCCESS,             11,
            { 0x1111, 0x2222, 0, 0, 0, 0, 0, 0 }, ex_fail_6 },
    { "1111::5555:",                                    STATUS_INVALID_PARAMETER,   11,
            { 0x1111, 0x5555, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1111::3333:4444:5555:6666:7777::",               STATUS_SUCCESS,             30,
            { 0x1111, 0, 0, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777 }, ex_fail_6 },
    { "1111:2222:::4444:5555:6666:1.2.3.4",             STATUS_SUCCESS,             11,
            { 0x1111, 0x2222, 0, 0, 0, 0, 0, 0 }, ex_fail_6 },
    { "1111::3333::5555:6666:1.2.3.4",                  STATUS_SUCCESS,             10,
            { 0x1111, 0, 0, 0, 0, 0, 0, 0x3333 }, ex_fail_6 },
    { "12345::6:7:8",                                   STATUS_INVALID_PARAMETER,   -1,
            { -1 } },
    { "1::001.2.3.4",                                   STATUS_SUCCESS,             12,
            { 0x100, 0, 0, 0, 0, 0, 0x201, 0x403 } },
    { "1::1.002.3.4",                                   STATUS_SUCCESS,             12,
            { 0x100, 0, 0, 0, 0, 0, 0x201, 0x403 } },
    { "1::0001.2.3.4",                                  STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.0002.3.4",                                  STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0xab01, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.256.4",                                   STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0x201, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.4294967296.4",                            STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0x201, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.18446744073709551616.4",                  STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0x201, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.256",                                   STATUS_INVALID_PARAMETER,   12,
            { 0x100, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.4294967296",                            STATUS_INVALID_PARAMETER,   19,
            { 0x100, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.18446744073709551616",                  STATUS_INVALID_PARAMETER,   29,
            { 0x100, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.300",                                   STATUS_INVALID_PARAMETER,   12,
            { 0x100, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.300.",                                  STATUS_INVALID_PARAMETER,   12,
            { 0x100, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2::1",                                      STATUS_INVALID_PARAMETER,   6,
            { 0x100, 0xab01, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.4::1",                                  STATUS_SUCCESS,             10,
            { 0x100, 0, 0, 0, 0, 0, 0x201, 0x403 }, ex_fail_6 },
    { "1::1.",                                          STATUS_INVALID_PARAMETER,   5,
            { 0x100, 0xab01, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2",                                         STATUS_INVALID_PARAMETER,   6,
            { 0x100, 0xab01, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.",                                        STATUS_INVALID_PARAMETER,   7,
            { 0x100, 0x201, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3",                                       STATUS_INVALID_PARAMETER,   8,
            { 0x100, 0x201, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.",                                      STATUS_INVALID_PARAMETER,   9,
            { 0x100, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.3.4",                                     STATUS_SUCCESS,             10,
            { 0x100, 0, 0, 0, 0, 0, 0x201, 0x403 } },
    { "1::1.2.3.900",                                   STATUS_INVALID_PARAMETER,   12,
            { 0x100, 0x201, 0xab03, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2.300.4",                                   STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0x201, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.256.3.4",                                   STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0xab01, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.256:3.4",                                   STATUS_INVALID_PARAMETER,   8,
            { 0x100, 0xab01, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1.2a.3.4",                                    STATUS_INVALID_PARAMETER,   6,
            { 0x100, 0xab01, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::256.2.3.4",                                   STATUS_INVALID_PARAMETER,   -1,
            { 0x100, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "1::1a.2.3.4",                                    STATUS_SUCCESS,             5,
            { 0x100, 0, 0, 0, 0, 0, 0, 0x1a00 }, ex_fail_6 },
    { "1::2::3",                                        STATUS_SUCCESS,             4,
            { 0x100, 0, 0, 0, 0, 0, 0, 0x200 }, ex_fail_6 },
    { "2001:0000:1234: 0000:0000:C1C0:ABCD:0876",       STATUS_INVALID_PARAMETER,   15,
            { 0x120, 0, 0x3412, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "2001:0000:1234:0000:0000:C1C0:ABCD:0876  0",     STATUS_SUCCESS,             39,
            { 0x120, 0, 0x3412, 0, 0, 0xc0c1, 0xcdab, 0x7608 }, ex_fail_6 },
    { "2001:1:1:1:1:1:255Z255X255Y255",                 STATUS_INVALID_PARAMETER,   18,
            { 0x120, 0x100, 0x100, 0x100, 0x100, 0x100, 0xabab, 0xabab } },
    { "2001::FFD3::57ab",                               STATUS_SUCCESS,             10,
            { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff }, ex_fail_6 },
    { ":",                                              STATUS_INVALID_PARAMETER,   0,
            { -1 } },
    { ":1111:2222:3333:4444:5555:6666:1.2.3.4",         STATUS_INVALID_PARAMETER,   0,
            { -1 } },
    { ":1111:2222:3333:4444:5555:6666:7777:8888",       STATUS_INVALID_PARAMETER,   0,
            { -1 } },
    { ":1111::",                                        STATUS_INVALID_PARAMETER,   0,
            { -1 } },
    { "::-1",                                           STATUS_SUCCESS,             2,
            { 0, 0, 0, 0, 0, 0, 0, 0 }, ex_fail_6 },
    { "::12345678",                                     STATUS_INVALID_PARAMETER,   10,
            { 0, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "::123456789",                                    STATUS_INVALID_PARAMETER,   11,
            { 0, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "::1234567890abcdef0",                            STATUS_INVALID_PARAMETER,   19,
            { 0, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab, 0xabab } },
    { "::0x80000000",                                   STATUS_SUCCESS,             3,
            { 0, 0, 0, 0, 0, 0, 0, 0xffff }, ex_fail_6 },
    { "::0x012345678",                                  STATUS_SUCCESS,             3,
            { 0, 0, 0, 0, 0, 0, 0, 0x7856 }, ex_fail_6 },
    { "::0x123456789",                                  STATUS_SUCCESS,             3,
            { 0, 0, 0, 0, 0, 0, 0, 0xffff }, ex_fail_6 },
    { "::0x1234567890abcdef0",                          STATUS_SUCCESS,             3,
            { 0, 0, 0, 0, 0, 0, 0, 0xffff }, ex_fail_6 },
    { "::.",                                            STATUS_SUCCESS,             2,
            { 0, 0, 0, 0, 0, 0, 0, 0 }, ex_fail_6 },
    { "::..",                                           STATUS_SUCCESS,             2,
            { 0, 0, 0, 0, 0, 0, 0, 0 }, ex_fail_6 },
    { "::...",                                          STATUS_SUCCESS,             2,
            { 0, 0, 0, 0, 0, 0, 0, 0 }, ex_fail_6 },
    { "XXXX:XXXX:XXXX:XXXX:XXXX:XXXX:1.2.3.4",          STATUS_INVALID_PARAMETER,   0,
            { -1 } },
    { "[::]",                                           STATUS_INVALID_PARAMETER,   0,
            { -1 }, ex_skip_6 },
};

static void init_ip6(IN6_ADDR* addr, const int src[8])
{
    unsigned int j;
    if (!src || src[0] == -1)
    {
        for (j = 0; j < 8; ++j)
            addr->s6_words[j] = 0xabab;
    }
    else
    {
        for (j = 0; j < 8; ++j)
            addr->s6_words[j] = src[j];
    }
}

static void test_RtlIpv6AddressToString(void)
{
    CHAR buffer[50];
    LPCSTR result;
    IN6_ADDR ip;
    DWORD_PTR len;
    static const struct
    {
        PCSTR address;
        int ip[8];
    } tests[] =
    {
        /* ipv4 addresses & ISATAP addresses */
        { "::13.1.68.3",                                { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },
        { "::123.123.123.123",                          { 0, 0, 0, 0, 0, 0, 0x7b7b, 0x7b7b } },
        { "::ffff",                                     { 0, 0, 0, 0, 0, 0, 0, 0xffff } },
        { "::0.1.0.0",                                  { 0, 0, 0, 0, 0, 0, 0x100, 0 } },
        { "::ffff:13.1.68.3",                           { 0, 0, 0, 0, 0, 0xffff, 0x10d, 0x344 } },
        { "::feff:d01:4403",                            { 0, 0, 0, 0, 0, 0xfffe, 0x10d, 0x344 } },
        { "::fffe:d01:4403",                            { 0, 0, 0, 0, 0, 0xfeff, 0x10d, 0x344 } },
        { "::100:d01:4403",                             { 0, 0, 0, 0, 0, 1, 0x10d, 0x344 } },
        { "::1:d01:4403",                               { 0, 0, 0, 0, 0, 0x100, 0x10d, 0x344 } },
        { "::1:0:d01:4403",                             { 0, 0, 0, 0, 0x100, 0, 0x10d, 0x344 } },
        { "::fffe:d01:4403",                            { 0, 0, 0, 0, 0, 0xfeff, 0x10d, 0x344 } },
        { "::fffe:0:d01:4403",                          { 0, 0, 0, 0, 0xfeff, 0, 0x10d, 0x344 } },
        { "::ffff:0:4403",                              { 0, 0, 0, 0, 0, 0xffff, 0, 0x344 } },
        { "::ffff:0.1.0.0",                             { 0, 0, 0, 0, 0, 0xffff, 0x100, 0 } },
        { "::ffff:13.1.0.0",                            { 0, 0, 0, 0, 0, 0xffff, 0x10d, 0 } },
        { "::ffff:0:0",                                 { 0, 0, 0, 0, 0, 0xffff, 0, 0 } },
        { "::ffff:0:ffff",                              { 0, 0, 0, 0, 0, 0xffff, 0, 0xffff } },
        { "::ffff:0:0.1.0.0",                           { 0, 0, 0, 0, 0xffff, 0, 0x100, 0 } },
        { "::ffff:0:13.1.68.3",                         { 0, 0, 0, 0, 0xffff, 0, 0x10d, 0x344 } },
        { "::ffff:ffff:d01:4403",                       { 0, 0, 0, 0, 0xffff, 0xffff, 0x10d, 0x344 } },
        { "::ffff:0:0:d01:4403",                        { 0, 0, 0, 0xffff, 0, 0, 0x10d, 0x344 } },
        { "::ffff:255.255.255.255",                     { 0, 0, 0, 0, 0, 0xffff, 0xffff, 0xffff } },
        { "::ffff:129.144.52.38",                       { 0, 0, 0, 0, 0, 0xffff, 0x9081, 0x2634 } },
        { "::5efe:0.0.0.0",                             { 0, 0, 0, 0, 0, 0xfe5e, 0, 0 } },
        { "::5efe:129.144.52.38",                       { 0, 0, 0, 0, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "1111:2222:3333:4444:0:5efe:129.144.52.38",   { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "1111:2222:3333::5efe:129.144.52.38",         { 0x1111, 0x2222, 0x3333, 0, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "1111:2222::5efe:129.144.52.38",              { 0x1111, 0x2222, 0, 0, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "1111::5efe:129.144.52.38",                   { 0x1111, 0, 0, 0, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "::300:5efe:8190:3426",                       { 0, 0, 0, 0, 3, 0xfe5e, 0x9081, 0x2634 } },
        { "::200:5efe:129.144.52.38",                   { 0, 0, 0, 0, 2, 0xfe5e, 0x9081, 0x2634 } },
        { "::100:5efe:8190:3426",                       { 0, 0, 0, 0, 1, 0xfe5e, 0x9081, 0x2634 } },
        /* 'normal' addresses */
        { "::1",                                        { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "::2",                                        { 0, 0, 0, 0, 0, 0, 0, 0x200 } },
        { "0:1:2:3:4:5:6:7",                            { 0, 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700 } },
        { "1080::8:800:200c:417a",                      { 0x8010, 0, 0, 0, 0x800, 0x8, 0x0c20, 0x7a41 } },
        { "1111:2222:3333:4444:5555:6666:7b7b:7b7b",    { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "1111:2222:3333:4444:5555:6666:7777:8888",    { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 } },
        { "1111:2222:3333:4444:5555:6666::",            { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0 } },
        { "1111:2222:3333:4444:5555:6666:0:8888",       { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0, 0x8888 } },
        { "1111:2222:3333:4444:5555::",                 { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0 } },
        { "1111:2222:3333:4444:5555:0:7b7b:7b7b",       { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0x7b7b, 0x7b7b } },
        { "1111:2222:3333:4444:5555:0:7777:8888",       { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0x7777, 0x8888 } },
        { "1111:2222:3333:4444:5555::8888",             { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0, 0, 0x8888 } },
        { "1111::",                                     { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },
        { "1111::7b7b:7b7b",                            { 0x1111, 0, 0, 0, 0, 0, 0x7b7b, 0x7b7b } },
        { "1111:0:3333:4444:5555:6666:7b7b:7b7b",       { 0x1111, 0, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "1111:0:3333:4444:5555:6666:7777:8888",       { 0x1111, 0, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 } },
        { "1111::4444:5555:6666:7b7b:7b7b",             { 0x1111, 0, 0, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "1111::4444:5555:6666:7777:8888",             { 0x1111, 0, 0, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 } },
        { "1111::5555:6666:7b7b:7b7b",                  { 0x1111, 0, 0, 0, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "1111::5555:6666:7777:8888",                  { 0x1111, 0, 0, 0, 0x5555, 0x6666, 0x7777, 0x8888 } },
        { "1111::6666:7b7b:7b7b",                       { 0x1111, 0, 0, 0, 0, 0x6666, 0x7b7b, 0x7b7b } },
        { "1111::6666:7777:8888",                       { 0x1111, 0, 0, 0, 0, 0x6666, 0x7777, 0x8888 } },
        { "1111::7777:8888",                            { 0x1111, 0, 0, 0, 0, 0, 0x7777, 0x8888 } },
        { "1111::8888",                                 { 0x1111, 0, 0, 0, 0, 0, 0, 0x8888 } },
        { "1:2:3:4:5:6:102:304",                        { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x201, 0x403 } },
        { "1:2:3:4:5:6:7:8",                            { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0x700, 0x800 } },
        { "1:2:3:4:5:6::",                              { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0, 0 } },
        { "1:2:3:4:5:6:0:8",                            { 0x100, 0x200, 0x300, 0x400, 0x500, 0x600, 0, 0x800 } },
        { "2001:0:1234::c1c0:abcd:876",                 { 0x120, 0, 0x3412, 0, 0, 0xc0c1, 0xcdab, 0x7608 } },
        { "2001:0:4136:e378:8000:63bf:3fff:fdd2",       { 0x120, 0, 0x3641, 0x78e3, 0x80, 0xbf63, 0xff3f, 0xd2fd } },
        { "2001:db8::1428:57ab",                        { 0x120, 0xb80d, 0, 0, 0, 0, 0x2814, 0xab57 } },
        { "2001:db8:1234:ffff:ffff:ffff:ffff:ffff",     { 0x120, 0xb80d, 0x3412, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff } },
        { "2001:0:ce49:7601:2cad:dfff:7c94:fffe",       { 0x120, 0, 0x49ce, 0x176, 0xad2c, 0xffdf, 0x947c, 0xfeff } },
        { "2001:db8:85a3::8a2e:370:7334",               { 0x120, 0xb80d, 0xa385, 0, 0, 0x2e8a, 0x7003, 0x3473 } },
        { "3ffe:b00::1:0:0:a",                          { 0xfe3f, 0xb, 0, 0, 0x100, 0, 0, 0xa00 } },
        { "::a:b:c:d:e",                                { 0, 0, 0, 0xa00, 0xb00, 0xc00, 0xd00, 0xe00 } },
        { "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",    { 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff } },
        { "1111:2222:3333:4444:5555:6666:7777:1",       { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x100 } },
        { "1111:2222:3333:4444:5555:6666:7777:8888",    { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777, 0x8888 } },
        { "1111:2222::",                                { 0x1111, 0x2222, 0, 0, 0, 0, 0, 0 } },
        { "1111::3333:4444:5555:6666:7777",             { 0x1111, 0, 0, 0x3333, 0x4444, 0x5555, 0x6666, 0x7777 } },
        { "1111:2222::",                                { 0x1111, 0x2222, 0, 0, 0, 0, 0, 0 } },
        { "1111::3333",                                 { 0x1111, 0, 0, 0, 0, 0, 0, 0x3333 } },
        { "2001:0:1234::c1c0:abcd:876",                 { 0x120, 0, 0x3412, 0, 0, 0xc0c1, 0xcdab, 0x7608 } },
        { "2001::ffd3",                                 { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff } },
    };
    unsigned int i;

    memset(buffer, '#', sizeof(buffer));
    buffer[sizeof(buffer)-1] = 0;
    memset(&ip, 0, sizeof(ip));
    result = RtlIpv6AddressToStringA(&ip, buffer);

    len = strlen(buffer);
    ok(result == (buffer + len) && !strcmp(buffer, "::"),
       "got %p with '%s' (expected %p with '::')\n", result, buffer, buffer + len);

    result = RtlIpv6AddressToStringA(&ip, NULL);
    ok(result == (LPCSTR)~0 || broken(result == (LPCSTR)len) /* WinXP / Win2k3 */,
       "got %p, expected %p\n", result, (LPCSTR)~0);

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        init_ip6(&ip, tests[i].ip);
        memset(buffer, '#', sizeof(buffer));
        buffer[sizeof(buffer)-1] = 0;

        result = RtlIpv6AddressToStringA(&ip, buffer);
        len = strlen(buffer);
        ok(result == (buffer + len) && !strcmp(buffer, tests[i].address),
           "got %p with '%s' (expected %p with '%s')\n", result, buffer, buffer + len, tests[i].address);

        ok(buffer[45] == 0 || broken(buffer[45] != 0) /* WinXP / Win2k3 */,
           "expected data at buffer[45] to always be NULL\n");
        ok(buffer[46] == '#', "expected data at buffer[46] not to change\n");
    }
}

static void test_RtlIpv6AddressToStringEx(void)
{
    CHAR buffer[70];
    NTSTATUS res;
    IN6_ADDR ip;
    ULONG len;
    static const struct
    {
        PCSTR address;
        ULONG scopeid;
        USHORT port;
        int ip[8];
    } tests[] =
    {
        /* ipv4 addresses & ISATAP addresses */
        { "::13.1.68.3",                                                0,          0, { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },
        { "::13.1.68.3%1",                                              1,          0, { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },
        { "::13.1.68.3%4294949819",                                     0xffffbbbb, 0, { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },
        { "[::13.1.68.3%4294949819]:65518",                             0xffffbbbb, 0xeeff, { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },
        { "[::13.1.68.3%4294949819]:256",                               0xffffbbbb, 1, { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },
        { "[::13.1.68.3]:256",                                          0,          1, { 0, 0, 0, 0, 0, 0, 0x10d, 0x344 } },

        { "::1:d01:4403",                                               0,          0, { 0, 0, 0, 0, 0, 0x100, 0x10d, 0x344 } },
        { "::1:d01:4403%1",                                             1,          0, { 0, 0, 0, 0, 0, 0x100, 0x10d, 0x344 } },
        { "::1:d01:4403%4294949819",                                    0xffffbbbb, 0, { 0, 0, 0, 0, 0, 0x100, 0x10d, 0x344 } },
        { "[::1:d01:4403%4294949819]:65518",                            0xffffbbbb, 0xeeff, { 0, 0, 0, 0, 0, 0x100, 0x10d, 0x344 } },
        { "[::1:d01:4403%4294949819]:256",                              0xffffbbbb, 1, { 0, 0, 0, 0, 0, 0x100, 0x10d, 0x344 } },
        { "[::1:d01:4403]:256",                                         0,          1, { 0, 0, 0, 0, 0, 0x100, 0x10d, 0x344 } },

        { "1111:2222:3333:4444:0:5efe:129.144.52.38",                   0,          0, { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "1111:2222:3333:4444:0:5efe:129.144.52.38%1",                 1,          0, { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "1111:2222:3333:4444:0:5efe:129.144.52.38%4294949819",        0xffffbbbb, 0, { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "[1111:2222:3333:4444:0:5efe:129.144.52.38%4294949819]:65518",0xffffbbbb, 0xeeff, { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "[1111:2222:3333:4444:0:5efe:129.144.52.38%4294949819]:256",  0xffffbbbb, 1, { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634 } },
        { "[1111:2222:3333:4444:0:5efe:129.144.52.38]:256",             0,          1, { 0x1111, 0x2222, 0x3333, 0x4444, 0, 0xfe5e, 0x9081, 0x2634 } },

        { "::1",                                                        0,          0, { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "::1%1",                                                      1,          0, { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "::1%4294949819",                                             0xffffbbbb, 0, { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[::1%4294949819]:65518",                                     0xffffbbbb, 0xeeff, { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[::1%4294949819]:256",                                       0xffffbbbb, 1, { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[::1]:256",                                                  0,          1, { 0, 0, 0, 0, 0, 0, 0, 0x100 } },

        { "1111:2222:3333:4444:5555:6666:7b7b:7b7b",                    0,          0, { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "1111:2222:3333:4444:5555:6666:7b7b:7b7b%1",                  1,          0, { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "1111:2222:3333:4444:5555:6666:7b7b:7b7b%4294949819",         0xffffbbbb, 0, { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "[1111:2222:3333:4444:5555:6666:7b7b:7b7b%4294949819]:65518", 0xffffbbbb, 0xeeff, { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "[1111:2222:3333:4444:5555:6666:7b7b:7b7b%4294949819]:256",   0xffffbbbb, 1, { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },
        { "[1111:2222:3333:4444:5555:6666:7b7b:7b7b]:256",              0,          1, { 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666, 0x7b7b, 0x7b7b } },

        { "1111::",                                                     0,          0, { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },
        { "1111::%1",                                                   1,          0, { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },
        { "1111::%4294949819",                                          0xffffbbbb, 0, { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },
        { "[1111::%4294949819]:65518",                                  0xffffbbbb, 0xeeff, { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },
        { "[1111::%4294949819]:256",                                    0xffffbbbb, 1, { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },
        { "[1111::]:256",                                               0,          1, { 0x1111, 0, 0, 0, 0, 0, 0, 0 } },

        { "2001::ffd3",                                                 0,          0, { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff } },
        { "2001::ffd3%1",                                               1,          0, { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff } },
        { "2001::ffd3%4294949819",                                      0xffffbbbb, 0, { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff } },
        { "[2001::ffd3%4294949819]:65518",                              0xffffbbbb, 0xeeff, { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff } },
        { "[2001::ffd3%4294949819]:256",                                0xffffbbbb, 1, { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff } },
        { "[2001::ffd3]:256",                                           0,          1, { 0x120, 0, 0, 0, 0, 0, 0, 0xd3ff } },
    };
    unsigned int i;

    if (!pRtlIpv6AddressToStringExA)
    {
        win_skip("RtlIpv6AddressToStringExA not available\n");
        return;
    }

    memset(buffer, '#', sizeof(buffer));
    buffer[sizeof(buffer)-1] = 0;
    memset(&ip, 0, sizeof(ip));
    len = sizeof(buffer);
    res = pRtlIpv6AddressToStringExA(&ip, 0, 0, buffer, &len);

    ok(res == STATUS_SUCCESS, "[validate] res = 0x%08lx, expected STATUS_SUCCESS\n", res);
    ok(len == 3 && !strcmp(buffer, "::"),
        "got len %ld with '%s' (expected 3 with '::')\n", len, buffer);

    memset(buffer, '#', sizeof(buffer));
    buffer[sizeof(buffer)-1] = 0;

    len = sizeof(buffer);
    res = pRtlIpv6AddressToStringExA(NULL, 0, 0, buffer, &len);
    ok(res == STATUS_INVALID_PARAMETER, "[null ip] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);

    len = sizeof(buffer);
    res = pRtlIpv6AddressToStringExA(&ip, 0, 0, NULL, &len);
    ok(res == STATUS_INVALID_PARAMETER, "[null buffer] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);

    res = pRtlIpv6AddressToStringExA(&ip, 0, 0, buffer, NULL);
    ok(res == STATUS_INVALID_PARAMETER, "[null length] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);

    len = 2;
    memset(buffer, '#', sizeof(buffer));
    buffer[sizeof(buffer)-1] = 0;
    res = pRtlIpv6AddressToStringExA(&ip, 0, 0, buffer, &len);
    ok(res == STATUS_INVALID_PARAMETER, "[null length] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
    ok(buffer[0] == '#', "got first char %c (expected '#')\n", buffer[0]);
    ok(len == 3, "got len %ld (expected len 3)\n", len);

    for (i = 0; i < ARRAY_SIZE(tests); i++)
    {
        init_ip6(&ip, tests[i].ip);
        len = sizeof(buffer);
        memset(buffer, '#', sizeof(buffer));
        buffer[sizeof(buffer)-1] = 0;

        res = pRtlIpv6AddressToStringExA(&ip, tests[i].scopeid, tests[i].port, buffer, &len);

        ok(res == STATUS_SUCCESS, "[validate] res = 0x%08lx, expected STATUS_SUCCESS\n", res);
        ok(len == (strlen(tests[i].address) + 1) && !strcmp(buffer, tests[i].address),
           "got len %ld with '%s' (expected %d with '%s')\n", len, buffer, (int)strlen(tests[i].address), tests[i].address);
    }
}

static void compare_RtlIpv6StringToAddressW(PCSTR name_a, int terminator_offset_a,
                                            const struct in6_addr *addr_a, NTSTATUS res_a)
{
    WCHAR name[512];
    NTSTATUS res;
    IN6_ADDR ip;
    PCWSTR terminator;

    RtlMultiByteToUnicodeN(name, sizeof(name), NULL, name_a, strlen(name_a) + 1);

    init_ip6(&ip, NULL);
    terminator = (void *)0xdeadbeef;
    res = RtlIpv6StringToAddressW(name, &terminator, &ip);
    ok(res == res_a, "[W:%s] res = 0x%08lx, expected 0x%08lx\n", name_a, res, res_a);

    if (terminator_offset_a < 0)
    {
        ok(terminator == (void *)0xdeadbeef,
           "[W:%s] terminator = %p, expected it not to change\n",
           name_a, terminator);
    }
    else
    {
        ok(terminator == name + terminator_offset_a,
           "[W:%s] terminator = %p, expected %p\n",
           name_a, terminator, name + terminator_offset_a);
    }

    ok(!memcmp(&ip, addr_a, sizeof(ip)),
       "[W:%s] ip = %x:%x:%x:%x:%x:%x:%x:%x, expected %x:%x:%x:%x:%x:%x:%x:%x\n",
       name_a,
       ip.s6_words[0], ip.s6_words[1], ip.s6_words[2], ip.s6_words[3],
       ip.s6_words[4], ip.s6_words[5], ip.s6_words[6], ip.s6_words[7],
       addr_a->s6_words[0], addr_a->s6_words[1], addr_a->s6_words[2], addr_a->s6_words[3],
       addr_a->s6_words[4], addr_a->s6_words[5], addr_a->s6_words[6], addr_a->s6_words[7]);
}

static void test_RtlIpv6StringToAddress(void)
{
    NTSTATUS res;
    IN6_ADDR ip, expected_ip;
    PCSTR terminator;
    unsigned int i;

    res = RtlIpv6StringToAddressA("::", &terminator, &ip);
    ok(res == STATUS_SUCCESS, "[validate] res = 0x%08lx, expected STATUS_SUCCESS\n", res);
    if (0)
    {
        /* any of these crash */
        res = RtlIpv6StringToAddressA(NULL, &terminator, &ip);
        ok(res == STATUS_INVALID_PARAMETER, "[null string] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
        res = RtlIpv6StringToAddressA("::", NULL, &ip);
        ok(res == STATUS_INVALID_PARAMETER, "[null terminator] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
        res = RtlIpv6StringToAddressA("::", &terminator, NULL);
        ok(res == STATUS_INVALID_PARAMETER, "[null result] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
    }

    /* sanity check */
    ok(sizeof(ip) == sizeof(USHORT)* 8, "sizeof(ip)\n");

    for (i = 0; i < ARRAY_SIZE(ipv6_tests); i++)
    {
        init_ip6(&ip, NULL);
        terminator = (void *)0xdeadbeef;
        res = RtlIpv6StringToAddressA(ipv6_tests[i].address, &terminator, &ip);
        compare_RtlIpv6StringToAddressW(ipv6_tests[i].address, (terminator != (void *)0xdeadbeef) ?
                                        (terminator - ipv6_tests[i].address) : -1, &ip, res);

        if (ipv6_tests[i].flags & win_broken_6)
        {
            ok(res == ipv6_tests[i].res || broken(res == STATUS_INVALID_PARAMETER),
               "[%s] res = 0x%08lx, expected 0x%08lx\n",
               ipv6_tests[i].address, res, ipv6_tests[i].res);

            if (res == STATUS_INVALID_PARAMETER)
                continue;
        }
        else
        {
            ok(res == ipv6_tests[i].res,
               "[%s] res = 0x%08lx, expected 0x%08lx\n",
               ipv6_tests[i].address, res, ipv6_tests[i].res);
        }

        if (ipv6_tests[i].terminator_offset < 0)
        {
            ok(terminator == (void *)0xdeadbeef,
               "[%s] terminator = %p, expected it not to change\n",
               ipv6_tests[i].address, terminator);
        }
        else
        {
            if (ipv6_tests[i].flags & win_extra_zero)
                ok(terminator == ipv6_tests[i].address + ipv6_tests[i].terminator_offset ||
                   broken(terminator != ipv6_tests[i].address + ipv6_tests[i].terminator_offset),
                   "[%s] terminator = %p, expected %p\n",
                   ipv6_tests[i].address, terminator, ipv6_tests[i].address + ipv6_tests[i].terminator_offset);
            else
                ok(terminator == ipv6_tests[i].address + ipv6_tests[i].terminator_offset,
                   "[%s] terminator = %p, expected %p\n",
                   ipv6_tests[i].address, terminator, ipv6_tests[i].address + ipv6_tests[i].terminator_offset);
        }

        init_ip6(&expected_ip, ipv6_tests[i].ip);
        if (ipv6_tests[i].flags & win_extra_zero)
            ok(!memcmp(&ip, &expected_ip, sizeof(ip)) || broken(memcmp(&ip, &expected_ip, sizeof(ip))),
               "[%s] ip = %x:%x:%x:%x:%x:%x:%x:%x, expected %x:%x:%x:%x:%x:%x:%x:%x\n",
               ipv6_tests[i].address, ip.s6_words[0], ip.s6_words[1], ip.s6_words[2], ip.s6_words[3],
               ip.s6_words[4], ip.s6_words[5], ip.s6_words[6], ip.s6_words[7],
               expected_ip.s6_words[0], expected_ip.s6_words[1], expected_ip.s6_words[2], expected_ip.s6_words[3],
               expected_ip.s6_words[4], expected_ip.s6_words[5], expected_ip.s6_words[6], expected_ip.s6_words[7]);
        else
            ok(!memcmp(&ip, &expected_ip, sizeof(ip)),
               "[%s] ip = %x:%x:%x:%x:%x:%x:%x:%x, expected %x:%x:%x:%x:%x:%x:%x:%x\n",
               ipv6_tests[i].address, ip.s6_words[0], ip.s6_words[1], ip.s6_words[2], ip.s6_words[3],
               ip.s6_words[4], ip.s6_words[5], ip.s6_words[6], ip.s6_words[7],
               expected_ip.s6_words[0], expected_ip.s6_words[1], expected_ip.s6_words[2], expected_ip.s6_words[3],
               expected_ip.s6_words[4], expected_ip.s6_words[5], expected_ip.s6_words[6], expected_ip.s6_words[7]);
    }
}

static void compare_RtlIpv6StringToAddressExW(PCSTR name_a, const struct in6_addr *addr_a, HRESULT res_a, ULONG scope_a, USHORT port_a)
{
    WCHAR name[512];
    NTSTATUS res;
    IN6_ADDR ip;
    ULONG scope = 0xbadf00d;
    USHORT port = 0xbeef;

    if (!pRtlIpv6StringToAddressExW)
        return;

    RtlMultiByteToUnicodeN(name, sizeof(name), NULL, name_a, strlen(name_a) + 1);

    init_ip6(&ip, NULL);
    res = pRtlIpv6StringToAddressExW(name, &ip, &scope, &port);

    ok(res == res_a, "[W:%s] res = 0x%08lx, expected 0x%08lx\n", name_a, res, res_a);
    ok(scope == scope_a, "[W:%s] scope = 0x%08lx, expected 0x%08lx\n", name_a, scope, scope_a);
    ok(port == port_a, "[W:%s] port = 0x%08x, expected 0x%08x\n", name_a, port, port_a);

    ok(!memcmp(&ip, addr_a, sizeof(ip)),
       "[W:%s] ip = %x:%x:%x:%x:%x:%x:%x:%x, expected %x:%x:%x:%x:%x:%x:%x:%x\n",
       name_a,
       ip.s6_words[0], ip.s6_words[1], ip.s6_words[2], ip.s6_words[3],
       ip.s6_words[4], ip.s6_words[5], ip.s6_words[6], ip.s6_words[7],
       addr_a->s6_words[0], addr_a->s6_words[1], addr_a->s6_words[2], addr_a->s6_words[3],
       addr_a->s6_words[4], addr_a->s6_words[5], addr_a->s6_words[6], addr_a->s6_words[7]);
}

static void test_RtlIpv6StringToAddressEx(void)
{
    NTSTATUS res;
    IN6_ADDR ip, expected_ip;
    ULONG scope;
    USHORT port;
    static const struct
    {
        PCSTR address;
        NTSTATUS res;
        ULONG scope;
        USHORT port;
        int ip[8];
    } ipv6_ex_tests[] =
    {
        { "[::]",                                           STATUS_SUCCESS,             0,          0,
            { 0, 0, 0, 0, 0, 0, 0, 0 } },
        { "[::1]:8080",                                     STATUS_SUCCESS,             0,          0x901f,
            { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[::1]:0x80",                                     STATUS_SUCCESS,             0,          0x8000,
            { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[::1]:0X80",                                     STATUS_SUCCESS,             0,          0x8000,
            { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[::1]:080",                                      STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[::1]:800000000080",                             STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0, 0, 0, 0, 0, 0, 0, 0x100 } },
        { "[FEDC:BA98:7654:3210:FEDC:BA98:7654:3210]:80",   STATUS_SUCCESS,             0,          0x5000,
            { 0xdcfe, 0x98ba, 0x5476, 0x1032, 0xdcfe, 0x98ba, 0x5476, 0x1032 } },
        { "[1080:0:0:0:8:800:200C:417A]:1234",              STATUS_SUCCESS,             0,          0xd204,
            { 0x8010, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[3ffe:2a00:100:7031::1]:8080",                   STATUS_SUCCESS,             0,          0x901f,
            { 0xfe3f, 0x2a, 1, 0x3170, 0, 0, 0, 0x100 } },
        { "[ 3ffe:2a00:100:7031::1]:8080",                  STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { -1 } },
        { "[3ffe:2a00:100:7031::1 ]:8080",                  STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0xfe3f, 0x2a, 1, 0x3170, 0, 0, 0, 0x100 } },
        { "[3ffe:2a00:100:7031::1].8080",                   STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0xfe3f, 0x2a, 1, 0x3170, 0, 0, 0, 0x100 } },
        { "[1080::8:800:200C:417A]:8080",                   STATUS_SUCCESS,             0,          0x901f,
            { 0x8010, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[1080::8:800:200C:417A]!8080",                   STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0x8010, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[::FFFF:129.144.52.38]:80",                      STATUS_SUCCESS,             0,          0x5000,
            { 0, 0, 0, 0, 0, 0xffff, 0x9081, 0x2634 } },
        { "[::FFFF:129.144.52.38]:-80",                     STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0, 0, 0, 0, 0, 0xffff, 0x9081, 0x2634 } },
        { "[::FFFF:129.144.52.38]:999999999999",            STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0, 0, 0, 0, 0, 0xffff, 0x9081, 0x2634 } },
        { "[::FFFF:129.144.52.38%-8]:80",                   STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0, 0, 0, 0, 0, 0xffff, 0x9081, 0x2634 } },
        { "[::FFFF:129.144.52.38]:80",                      STATUS_SUCCESS,             0,          0x5000,
            { 0, 0, 0, 0, 0, 0xffff, 0x9081, 0x2634 } },
        { "[12345::6:7:8]:80",                              STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { -1 } },
        { "[ff01::8:800:200C:417A%16]:8080",                STATUS_SUCCESS,             16,         0x901f,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%100]:8080",               STATUS_SUCCESS,             100,        0x901f,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%1000]:8080",              STATUS_SUCCESS,             1000,       0x901f,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%10000]:8080",             STATUS_SUCCESS,             10000,      0x901f,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%1000000]:8080",           STATUS_SUCCESS,             1000000,    0x901f,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%4294967295]:8080",        STATUS_SUCCESS,             0xffffffff, 0x901f,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%4294967296]:8080",        STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%-1]:8080",                STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%0]:8080",                 STATUS_SUCCESS,             0,          0x901f,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%1",                       STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A%0x1000]:8080",            STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
        { "[ff01::8:800:200C:417A/16]:8080",                STATUS_INVALID_PARAMETER,   0xbadf00d,  0xbeef,
            { 0x1ff, 0, 0, 0, 0x800, 8, 0xc20, 0x7a41 } },
    };
    const char *simple_ip = "::";
    unsigned int i;

    if (!pRtlIpv6StringToAddressExW)
    {
        win_skip("RtlIpv6StringToAddressExW not available\n");
        /* we can continue, just not test W */
    }

    if (!pRtlIpv6StringToAddressExA)
    {
        win_skip("RtlIpv6StringToAddressExA not available\n");
        return;
    }

    res = pRtlIpv6StringToAddressExA(simple_ip, &ip, &scope, &port);
    ok(res == STATUS_SUCCESS, "[validate] res = 0x%08lx, expected STATUS_SUCCESS\n", res);

    init_ip6(&ip, NULL);
    init_ip6(&expected_ip, NULL);
    scope = 0xbadf00d;
    port = 0xbeef;
    res = pRtlIpv6StringToAddressExA(NULL, &ip, &scope, &port);
    ok(res == STATUS_INVALID_PARAMETER,
       "[null string] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
    ok(scope == 0xbadf00d, "[null string] scope = 0x%08lx, expected 0xbadf00d\n", scope);
    ok(port == 0xbeef, "[null string] port = 0x%08x, expected 0xbeef\n", port);
    ok(!memcmp(&ip, &expected_ip, sizeof(ip)),
       "[null string] ip is changed, expected it not to change\n");


    init_ip6(&ip, NULL);
    scope = 0xbadf00d;
    port = 0xbeef;
    res = pRtlIpv6StringToAddressExA(simple_ip, NULL, &scope, &port);
    ok(res == STATUS_INVALID_PARAMETER,
       "[null result] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
    ok(scope == 0xbadf00d, "[null result] scope = 0x%08lx, expected 0xbadf00d\n", scope);
    ok(port == 0xbeef, "[null result] port = 0x%08x, expected 0xbeef\n", port);
    ok(!memcmp(&ip, &expected_ip, sizeof(ip)),
       "[null result] ip is changed, expected it not to change\n");

    init_ip6(&ip, NULL);
    scope = 0xbadf00d;
    port = 0xbeef;
    res = pRtlIpv6StringToAddressExA(simple_ip, &ip, NULL, &port);
    ok(res == STATUS_INVALID_PARAMETER,
       "[null scope] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
    ok(scope == 0xbadf00d, "[null scope] scope = 0x%08lx, expected 0xbadf00d\n", scope);
    ok(port == 0xbeef, "[null scope] port = 0x%08x, expected 0xbeef\n", port);
    ok(!memcmp(&ip, &expected_ip, sizeof(ip)),
       "[null scope] ip is changed, expected it not to change\n");

    init_ip6(&ip, NULL);
    scope = 0xbadf00d;
    port = 0xbeef;
    res = pRtlIpv6StringToAddressExA(simple_ip, &ip, &scope, NULL);
    ok(res == STATUS_INVALID_PARAMETER,
       "[null port] res = 0x%08lx, expected STATUS_INVALID_PARAMETER\n", res);
    ok(scope == 0xbadf00d, "[null port] scope = 0x%08lx, expected 0xbadf00d\n", scope);
    ok(port == 0xbeef, "[null port] port = 0x%08x, expected 0xbeef\n", port);
    ok(!memcmp(&ip, &expected_ip, sizeof(ip)),
       "[null port] ip is changed, expected it not to change\n");

    /* sanity check */
    ok(sizeof(ip) == sizeof(USHORT)* 8, "sizeof(ip)\n");

    /* first we run all ip related tests, to make sure someone didn't accidentally reimplement instead of re-use. */
    for (i = 0; i < ARRAY_SIZE(ipv6_tests); i++)
    {
        ULONG scope = 0xbadf00d;
        USHORT port = 0xbeef;
        NTSTATUS expect_ret = (ipv6_tests[i].flags & ex_fail_6) ? STATUS_INVALID_PARAMETER : ipv6_tests[i].res;

        if (ipv6_tests[i].flags & ex_skip_6)
            continue;

        init_ip6(&ip, NULL);
        res = pRtlIpv6StringToAddressExA(ipv6_tests[i].address, &ip, &scope, &port);
        compare_RtlIpv6StringToAddressExW(ipv6_tests[i].address, &ip, res, scope, port);

        /* make sure nothing was changed if this function fails. */
        if (res == STATUS_INVALID_PARAMETER)
        {
            ok(scope == 0xbadf00d, "[%s] scope = 0x%08lx, expected 0xbadf00d\n",
               ipv6_tests[i].address, scope);
            ok(port == 0xbeef, "[%s] port = 0x%08x, expected 0xbeef\n",
               ipv6_tests[i].address, port);
        }
        else
        {
            ok(scope != 0xbadf00d, "[%s] scope = 0x%08lx, not expected 0xbadf00d\n",
               ipv6_tests[i].address, scope);
            ok(port != 0xbeef, "[%s] port = 0x%08x, not expected 0xbeef\n",
               ipv6_tests[i].address, port);
        }

        if (ipv6_tests[i].flags & win_broken_6)
        {
            ok(res == expect_ret || broken(res == STATUS_INVALID_PARAMETER),
               "[%s] res = 0x%08lx, expected 0x%08lx\n", ipv6_tests[i].address, res, expect_ret);

            if (res == STATUS_INVALID_PARAMETER)
                continue;
        }
        else
        {
            ok(res == expect_ret, "[%s] res = 0x%08lx, expected 0x%08lx\n",
               ipv6_tests[i].address, res, expect_ret);
        }

        /* If ex fails but non-ex does not we cannot check if the part that is converted
           before it failed was correct, since there is no data for it in the table. */
        if (res == expect_ret)
        {
            init_ip6(&expected_ip, ipv6_tests[i].ip);
            ok(!memcmp(&ip, &expected_ip, sizeof(ip)),
               "[%s] ip = %x:%x:%x:%x:%x:%x:%x:%x, expected %x:%x:%x:%x:%x:%x:%x:%x\n",
               ipv6_tests[i].address,
               ip.s6_words[0], ip.s6_words[1], ip.s6_words[2], ip.s6_words[3],
               ip.s6_words[4], ip.s6_words[5], ip.s6_words[6], ip.s6_words[7],
               expected_ip.s6_words[0], expected_ip.s6_words[1], expected_ip.s6_words[2], expected_ip.s6_words[3],
               expected_ip.s6_words[4], expected_ip.s6_words[5], expected_ip.s6_words[6], expected_ip.s6_words[7]);
        }
    }

    /* now we run scope / port related tests */
    for (i = 0; i < ARRAY_SIZE(ipv6_ex_tests); i++)
    {
        scope = 0xbadf00d;
        port = 0xbeef;
        init_ip6(&ip, NULL);
        res = pRtlIpv6StringToAddressExA(ipv6_ex_tests[i].address, &ip, &scope, &port);
        compare_RtlIpv6StringToAddressExW(ipv6_ex_tests[i].address, &ip, res, scope, port);

        ok(res == ipv6_ex_tests[i].res, "[%s] res = 0x%08lx, expected 0x%08lx\n",
           ipv6_ex_tests[i].address, res, ipv6_ex_tests[i].res);
        ok(scope == ipv6_ex_tests[i].scope, "[%s] scope = 0x%08lx, expected 0x%08lx\n",
           ipv6_ex_tests[i].address, scope, ipv6_ex_tests[i].scope);
        ok(port == ipv6_ex_tests[i].port, "[%s] port = 0x%08x, expected 0x%08x\n",
           ipv6_ex_tests[i].address, port, ipv6_ex_tests[i].port);

        init_ip6(&expected_ip, ipv6_ex_tests[i].ip);
        ok(!memcmp(&ip, &expected_ip, sizeof(ip)),
           "[%s] ip = %x:%x:%x:%x:%x:%x:%x:%x, expected %x:%x:%x:%x:%x:%x:%x:%x\n",
           ipv6_ex_tests[i].address,
           ip.s6_words[0], ip.s6_words[1], ip.s6_words[2], ip.s6_words[3],
           ip.s6_words[4], ip.s6_words[5], ip.s6_words[6], ip.s6_words[7],
           expected_ip.s6_words[0], expected_ip.s6_words[1], expected_ip.s6_words[2], expected_ip.s6_words[3],
           expected_ip.s6_words[4], expected_ip.s6_words[5], expected_ip.s6_words[6], expected_ip.s6_words[7]);
    }
}

static void test_LdrAddRefDll(void)
{
    HMODULE mod, mod2;
    NTSTATUS status;
    BOOL ret;

    mod = LoadLibraryA("comctl32.dll");
    ok(mod != NULL, "got %p\n", mod);
    ret = FreeLibrary(mod);
    ok(ret, "got %d\n", ret);

    mod2 = GetModuleHandleA("comctl32.dll");
    ok(mod2 == NULL, "got %p\n", mod2);

    /* load, addref and release 2 times */
    mod = LoadLibraryA("comctl32.dll");
    ok(mod != NULL, "got %p\n", mod);
    status = LdrAddRefDll(0, mod);
    ok(status == STATUS_SUCCESS, "got 0x%08lx\n", status);
    ret = FreeLibrary(mod);
    ok(ret, "got %d\n", ret);

    mod2 = GetModuleHandleA("comctl32.dll");
    ok(mod2 != NULL, "got %p\n", mod2);
    ret = FreeLibrary(mod);
    ok(ret, "got %d\n", ret);

    mod2 = GetModuleHandleA("comctl32.dll");
    ok(mod2 == NULL, "got %p\n", mod2);

    /* pin refcount */
    mod = LoadLibraryA("comctl32.dll");
    ok(mod != NULL, "got %p\n", mod);
    status = LdrAddRefDll(LDR_ADDREF_DLL_PIN, mod);
    ok(status == STATUS_SUCCESS, "got 0x%08lx\n", status);

    ret = FreeLibrary(mod);
    ok(ret, "got %d\n", ret);
    ret = FreeLibrary(mod);
    ok(ret, "got %d\n", ret);
    ret = FreeLibrary(mod);
    ok(ret, "got %d\n", ret);
    ret = FreeLibrary(mod);
    ok(ret, "got %d\n", ret);

    mod2 = GetModuleHandleA("comctl32.dll");
    ok(mod2 != NULL, "got %p\n", mod2);
}

static void test_LdrLockLoaderLock(void)
{
    ULONG_PTR magic;
    ULONG result;
    NTSTATUS status;

    /* invalid flags */
    result = 10;
    magic = 0xdeadbeef;
    status = LdrLockLoaderLock(0x10, &result, &magic);
    ok(status == STATUS_INVALID_PARAMETER_1, "got 0x%08lx\n", status);
    ok(result == 0, "got %ld\n", result);
    ok(magic == 0, "got %Ix\n", magic);

    magic = 0xdeadbeef;
    status = LdrLockLoaderLock(0x10, NULL, &magic);
    ok(status == STATUS_INVALID_PARAMETER_1, "got 0x%08lx\n", status);
    ok(magic == 0, "got %Ix\n", magic);

    result = 10;
    status = LdrLockLoaderLock(0x10, &result, NULL);
    ok(status == STATUS_INVALID_PARAMETER_1, "got 0x%08lx\n", status);
    ok(result == 0, "got %ld\n", result);

    /* non-blocking mode, result is null */
    magic = 0xdeadbeef;
    status = LdrLockLoaderLock(0x2, NULL, &magic);
    ok(status == STATUS_INVALID_PARAMETER_2, "got 0x%08lx\n", status);
    ok(magic == 0, "got %Ix\n", magic);

    /* magic pointer is null */
    result = 10;
    status = LdrLockLoaderLock(0, &result, NULL);
    ok(status == STATUS_INVALID_PARAMETER_3, "got 0x%08lx\n", status);
    ok(result == 0, "got %ld\n", result);

    /* lock in non-blocking mode */
    result = 0;
    magic = 0;
    status = LdrLockLoaderLock(0x2, &result, &magic);
    ok(status == STATUS_SUCCESS, "got 0x%08lx\n", status);
    ok(result == 1, "got %ld\n", result);
    ok(magic != 0, "got %Ix\n", magic);
    LdrUnlockLoaderLock(0, magic);
}

static void test_RtlCompressBuffer(void)
{
    ULONG compress_workspace, decompress_workspace;
    static UCHAR test_buffer[] = "WineWineWine";
    static UCHAR buf1[0x1000], buf2[0x1000];
    ULONG final_size, buf_size;
    UCHAR *workspace = NULL;
    NTSTATUS status;

    compress_workspace = decompress_workspace = 0xdeadbeef;
    status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &compress_workspace,
                                            &decompress_workspace);
    ok(status == STATUS_SUCCESS, "got wrong status 0x%08lx\n", status);
    ok(compress_workspace != 0, "got wrong compress_workspace %lu\n", compress_workspace);
    workspace = HeapAlloc(GetProcessHeap(), 0, compress_workspace);
    ok(workspace != NULL, "HeapAlloc failed %ld\n", GetLastError());

    /* test compression format / engine */
    final_size = 0xdeadbeef;
    status = RtlCompressBuffer(COMPRESSION_FORMAT_NONE, test_buffer, sizeof(test_buffer),
                               buf1, sizeof(buf1) - 1, 4096, &final_size, workspace);
    ok(status == STATUS_INVALID_PARAMETER, "got wrong status 0x%08lx\n", status);
    ok(final_size == 0xdeadbeef, "got wrong final_size %lu\n", final_size);

    final_size = 0xdeadbeef;
    status = RtlCompressBuffer(COMPRESSION_FORMAT_DEFAULT, test_buffer, sizeof(test_buffer),
                               buf1, sizeof(buf1) - 1, 4096, &final_size, workspace);
    ok(status == STATUS_INVALID_PARAMETER, "got wrong status 0x%08lx\n", status);
    ok(final_size == 0xdeadbeef, "got wrong final_size %lu\n", final_size);

    final_size = 0xdeadbeef;
    status = RtlCompressBuffer(0xFF, test_buffer, sizeof(test_buffer),
                               buf1, sizeof(buf1) - 1, 4096, &final_size, workspace);
    ok(status == STATUS_UNSUPPORTED_COMPRESSION, "got wrong status 0x%08lx\n", status);
    ok(final_size == 0xdeadbeef, "got wrong final_size %lu\n", final_size);

    /* test compression */
    final_size = 0xdeadbeef;
    memset(buf1, 0x11, sizeof(buf1));
    status = RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1, test_buffer, sizeof(test_buffer),
                               buf1, sizeof(buf1), 4096, &final_size, workspace);
    ok(status == STATUS_SUCCESS, "got wrong status 0x%08lx\n", status);
    ok((*(WORD *)buf1 & 0x7000) == 0x3000, "no chunk signature found %04x\n", *(WORD *)buf1);
    todo_wine
    ok(final_size < sizeof(test_buffer), "got wrong final_size %lu\n", final_size);

    /* test decompression */
    buf_size = final_size;
    final_size = 0xdeadbeef;
    memset(buf2, 0x11, sizeof(buf2));
    status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, buf2, sizeof(buf2),
                                 buf1, buf_size, &final_size);
    ok(status == STATUS_SUCCESS, "got wrong status 0x%08lx\n", status);
    ok(final_size == sizeof(test_buffer), "got wrong final_size %lu\n", final_size);
    ok(!memcmp(buf2, test_buffer, sizeof(test_buffer)), "got wrong decoded data\n");
    ok(buf2[sizeof(test_buffer)] == 0x11, "too many bytes written\n");

    /* buffer too small */
    final_size = 0xdeadbeef;
    memset(buf1, 0x11, sizeof(buf1));
    status = RtlCompressBuffer(COMPRESSION_FORMAT_LZNT1, test_buffer, sizeof(test_buffer),
                               buf1, 4, 4096, &final_size, workspace);
    ok(status == STATUS_BUFFER_TOO_SMALL, "got wrong status 0x%08lx\n", status);

    HeapFree(GetProcessHeap(), 0, workspace);
}

static void test_RtlGetCompressionWorkSpaceSize(void)
{
    ULONG compress_workspace, decompress_workspace;
    NTSTATUS status;

    /* test invalid format / engine */
    status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_NONE, &compress_workspace,
                                            &decompress_workspace);
    ok(status == STATUS_INVALID_PARAMETER, "got wrong status 0x%08lx\n", status);

    status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_DEFAULT, &compress_workspace,
                                            &decompress_workspace);
    ok(status == STATUS_INVALID_PARAMETER, "got wrong status 0x%08lx\n", status);

    status = RtlGetCompressionWorkSpaceSize(0xFF, &compress_workspace, &decompress_workspace);
    ok(status == STATUS_UNSUPPORTED_COMPRESSION, "got wrong status 0x%08lx\n", status);

    /* test LZNT1 with normal and maximum compression */
    compress_workspace = decompress_workspace = 0xdeadbeef;
    status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1, &compress_workspace,
                                            &decompress_workspace);
    ok(status == STATUS_SUCCESS, "got wrong status 0x%08lx\n", status);
    ok(compress_workspace != 0, "got wrong compress_workspace %lu\n", compress_workspace);
    ok(decompress_workspace == 0x1000, "got wrong decompress_workspace %lu\n", decompress_workspace);

    compress_workspace = decompress_workspace = 0xdeadbeef;
    status = RtlGetCompressionWorkSpaceSize(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM,
                                            &compress_workspace, &decompress_workspace);
    ok(status == STATUS_SUCCESS, "got wrong status 0x%08lx\n", status);
    ok(compress_workspace != 0, "got wrong compress_workspace %lu\n", compress_workspace);
    ok(decompress_workspace == 0x1000, "got wrong decompress_workspace %lu\n", decompress_workspace);
}

/* helper for test_RtlDecompressBuffer, checks if a chunk is incomplete */
static BOOL is_incomplete_chunk(const UCHAR *compressed, ULONG compressed_size, BOOL check_all)
{
    ULONG chunk_size;

    if (compressed_size <= sizeof(WORD))
        return TRUE;

    while (compressed_size >= sizeof(WORD))
    {
        chunk_size = (*(WORD *)compressed & 0xFFF) + 1;
        if (compressed_size < sizeof(WORD) + chunk_size)
            return TRUE;
        if (!check_all)
            break;
        compressed      += sizeof(WORD) + chunk_size;
        compressed_size -= sizeof(WORD) + chunk_size;
    }

    return FALSE;
}

#define DECOMPRESS_BROKEN_FRAGMENT     1 /* < Win 7 */
#define DECOMPRESS_BROKEN_TRUNCATED    2 /* broken on all machines */

static void test_RtlDecompressBuffer(void)
{
    static struct
    {
        UCHAR compressed[32];
        ULONG compressed_size;
        NTSTATUS status;
        UCHAR uncompressed[32];
        ULONG uncompressed_size;
        DWORD broken_flags;
    }
    test_lznt[] =
    {
        /* 4 byte uncompressed chunk */
        {
            {0x03, 0x30, 'W', 'i', 'n', 'e'},
            6,
            STATUS_SUCCESS,
            "Wine",
            4,
            DECOMPRESS_BROKEN_FRAGMENT
        },
        /* 8 byte uncompressed chunk */
        {
            {0x07, 0x30, 'W', 'i', 'n', 'e', 'W', 'i', 'n', 'e'},
            10,
            STATUS_SUCCESS,
            "WineWine",
            8,
            DECOMPRESS_BROKEN_FRAGMENT
        },
        /* 4 byte compressed chunk */
        {
            {0x04, 0xB0, 0x00, 'W', 'i', 'n', 'e'},
            7,
            STATUS_SUCCESS,
            "Wine",
            4
        },
        /* 8 byte compressed chunk */
        {
            {0x08, 0xB0, 0x00, 'W', 'i', 'n', 'e', 'W', 'i', 'n', 'e'},
            11,
            STATUS_SUCCESS,
            "WineWine",
            8
        },
        /* compressed chunk using backwards reference */
        {
            {0x06, 0xB0, 0x10, 'W', 'i', 'n', 'e', 0x01, 0x30},
            9,
            STATUS_SUCCESS,
            "WineWine",
            8,
            DECOMPRESS_BROKEN_TRUNCATED
        },
        /* compressed chunk using backwards reference with length > bytes_read */
        {
            {0x06, 0xB0, 0x10, 'W', 'i', 'n', 'e', 0x05, 0x30},
            9,
            STATUS_SUCCESS,
            "WineWineWine",
            12,
            DECOMPRESS_BROKEN_TRUNCATED
        },
        /* same as above, but unused bits != 0 */
        {
            {0x06, 0xB0, 0x30, 'W', 'i', 'n', 'e', 0x01, 0x30},
            9,
            STATUS_SUCCESS,
            "WineWine",
            8,
            DECOMPRESS_BROKEN_TRUNCATED
        },
        /* compressed chunk without backwards reference and unused bits != 0 */
        {
            {0x01, 0xB0, 0x02, 'W'},
            4,
            STATUS_SUCCESS,
            "W",
            1
        },
        /* termination sequence after first chunk */
        {
            {0x03, 0x30, 'W', 'i', 'n', 'e', 0x00, 0x00, 0x03, 0x30, 'W', 'i', 'n', 'e'},
            14,
            STATUS_SUCCESS,
            "Wine",
            4,
            DECOMPRESS_BROKEN_FRAGMENT
        },
        /* compressed chunk using backwards reference with 4 bit offset, 12 bit length */
        {
            {0x14, 0xB0, 0x00, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         0x00, 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                         0x01, 0x01, 0xF0},
            23,
            STATUS_SUCCESS,
            "ABCDEFGHIJKLMNOPABCD",
            20,
            DECOMPRESS_BROKEN_TRUNCATED
        },
        /* compressed chunk using backwards reference with 5 bit offset, 11 bit length */
        {
            {0x15, 0xB0, 0x00, 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                         0x00, 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                         0x02, 'A', 0x00, 0x78},
            24,
            STATUS_SUCCESS,
            "ABCDEFGHIJKLMNOPABCD",
            20,
            DECOMPRESS_BROKEN_TRUNCATED
        },
        /* uncompressed chunk with invalid magic */
        {
            {0x03, 0x20, 'W', 'i', 'n', 'e'},
            6,
            STATUS_SUCCESS,
            "Wine",
            4,
            DECOMPRESS_BROKEN_FRAGMENT
        },
        /* compressed chunk with invalid magic */
        {
            {0x04, 0xA0, 0x00, 'W', 'i', 'n', 'e'},
            7,
            STATUS_SUCCESS,
            "Wine",
            4
        },
        /* garbage byte after end of buffer */
        {
            {0x00, 0xB0, 0x02, 0x01},
            4,
            STATUS_SUCCESS,
            "",
            0
        },
        /* empty compressed chunk */
        {
            {0x00, 0xB0, 0x00},
            3,
            STATUS_SUCCESS,
            "",
            0
        },
        /* empty compressed chunk with unused bits != 0 */
        {
            {0x00, 0xB0, 0x01},
            3,
            STATUS_SUCCESS,
            "",
            0
        },
        /* empty input buffer */
        {
            {},
            0,
            STATUS_BAD_COMPRESSION_BUFFER,
        },
        /* incomplete chunk header */
        {
            {0x01},
            1,
            STATUS_BAD_COMPRESSION_BUFFER
        },
        /* incomplete chunk header */
        {
            {0x00, 0x30},
            2,
            STATUS_BAD_COMPRESSION_BUFFER
        },
        /* compressed chunk with invalid backwards reference */
        {
            {0x06, 0xB0, 0x10, 'W', 'i', 'n', 'e', 0x05, 0x40},
            9,
            STATUS_BAD_COMPRESSION_BUFFER
        },
        /* compressed chunk with incomplete backwards reference */
        {
            {0x05, 0xB0, 0x10, 'W', 'i', 'n', 'e', 0x05},
            8,
            STATUS_BAD_COMPRESSION_BUFFER
        },
        /* incomplete uncompressed chunk */
        {
            {0x07, 0x30, 'W', 'i', 'n', 'e'},
            6,
            STATUS_BAD_COMPRESSION_BUFFER
        },
        /* incomplete compressed chunk */
        {
            {0x08, 0xB0, 0x00, 'W', 'i', 'n', 'e'},
            7,
            STATUS_BAD_COMPRESSION_BUFFER
        },
        /* two compressed chunks, the second one incomplete */
        {
            {0x00, 0xB0, 0x02, 0x00, 0xB0},
            5,
            STATUS_BAD_COMPRESSION_BUFFER,
        }
    };

    static UCHAR buf[0x2000], workspace[0x1000];
    NTSTATUS status, expected_status;
    ULONG final_size;
    int i;

    /* test compression format / engine */
    final_size = 0xdeadbeef;
    status = RtlDecompressBuffer(COMPRESSION_FORMAT_NONE, buf, sizeof(buf), test_lznt[0].compressed,
                                 test_lznt[0].compressed_size, &final_size);
    ok(status == STATUS_INVALID_PARAMETER, "got wrong status 0x%08lx\n", status);
    ok(final_size == 0xdeadbeef, "got wrong final_size %lu\n", final_size);

    final_size = 0xdeadbeef;
    status = RtlDecompressBuffer(COMPRESSION_FORMAT_DEFAULT, buf, sizeof(buf), test_lznt[0].compressed,
                                 test_lznt[0].compressed_size, &final_size);
    ok(status == STATUS_INVALID_PARAMETER, "got wrong status 0x%08lx\n", status);
    ok(final_size == 0xdeadbeef, "got wrong final_size %lu\n", final_size);

    final_size = 0xdeadbeef;
    status = RtlDecompressBuffer(0xFF, buf, sizeof(buf), test_lznt[0].compressed,
                                 test_lznt[0].compressed_size, &final_size);
    ok(status == STATUS_UNSUPPORTED_COMPRESSION, "got wrong status 0x%08lx\n", status);
    ok(final_size == 0xdeadbeef, "got wrong final_size %lu\n", final_size);

    /* regular tests for RtlDecompressBuffer */
    for (i = 0; i < ARRAY_SIZE(test_lznt); i++)
    {
        trace("Running test %d (compressed_size=%lu, uncompressed_size=%lu, status=0x%08lx)\n",
              i, test_lznt[i].compressed_size, test_lznt[i].uncompressed_size, test_lznt[i].status);

        /* test with very big buffer */
        final_size = 0xdeadbeef;
        memset(buf, 0x11, sizeof(buf));
        status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, buf, sizeof(buf), test_lznt[i].compressed,
                                     test_lznt[i].compressed_size, &final_size);
        ok(status == test_lznt[i].status || broken(status == STATUS_BAD_COMPRESSION_BUFFER &&
           (test_lznt[i].broken_flags & DECOMPRESS_BROKEN_FRAGMENT)), "%d: got wrong status 0x%08lx\n", i, status);
        if (!status)
        {
            ok(final_size == test_lznt[i].uncompressed_size,
               "%d: got wrong final_size %lu\n", i, final_size);
            ok(!memcmp(buf, test_lznt[i].uncompressed, test_lznt[i].uncompressed_size),
               "%d: got wrong decoded data\n", i);
            ok(buf[test_lznt[i].uncompressed_size] == 0x11,
               "%d: buf[%lu] was modified\n", i, test_lznt[i].uncompressed_size);
        }

        /* test that modifier for compression engine is ignored */
        final_size = 0xdeadbeef;
        memset(buf, 0x11, sizeof(buf));
        status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1 | COMPRESSION_ENGINE_MAXIMUM, buf, sizeof(buf),
                                     test_lznt[i].compressed, test_lznt[i].compressed_size, &final_size);
        ok(status == test_lznt[i].status || broken(status == STATUS_BAD_COMPRESSION_BUFFER &&
           (test_lznt[i].broken_flags & DECOMPRESS_BROKEN_FRAGMENT)), "%d: got wrong status 0x%08lx\n", i, status);
        if (!status)
        {
            ok(final_size == test_lznt[i].uncompressed_size,
               "%d: got wrong final_size %lu\n", i, final_size);
            ok(!memcmp(buf, test_lznt[i].uncompressed, test_lznt[i].uncompressed_size),
               "%d: got wrong decoded data\n", i);
            ok(buf[test_lznt[i].uncompressed_size] == 0x11,
               "%d: buf[%lu] was modified\n", i, test_lznt[i].uncompressed_size);
        }

        /* test with expected output size */
        if (test_lznt[i].uncompressed_size > 0)
        {
            final_size = 0xdeadbeef;
            memset(buf, 0x11, sizeof(buf));
            status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, buf, test_lznt[i].uncompressed_size,
                                         test_lznt[i].compressed, test_lznt[i].compressed_size, &final_size);
            ok(status == test_lznt[i].status, "%d: got wrong status 0x%08lx\n", i, status);
            if (!status)
            {
                ok(final_size == test_lznt[i].uncompressed_size,
                   "%d: got wrong final_size %lu\n", i, final_size);
                ok(!memcmp(buf, test_lznt[i].uncompressed, test_lznt[i].uncompressed_size),
                   "%d: got wrong decoded data\n", i);
                ok(buf[test_lznt[i].uncompressed_size] == 0x11,
                   "%d: buf[%lu] was modified\n", i, test_lznt[i].uncompressed_size);
            }
        }

        /* test with smaller output size */
        if (test_lznt[i].uncompressed_size > 1)
        {
            final_size = 0xdeadbeef;
            memset(buf, 0x11, sizeof(buf));
            status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, buf, test_lznt[i].uncompressed_size - 1,
                                         test_lznt[i].compressed, test_lznt[i].compressed_size, &final_size);
            ok(status == test_lznt[i].status ||
               broken(status == STATUS_BAD_COMPRESSION_BUFFER && (test_lznt[i].broken_flags & DECOMPRESS_BROKEN_TRUNCATED)),
               "%d: got wrong status 0x%08lx\n", i, status);
            if (!status)
            {
                ok(final_size == test_lznt[i].uncompressed_size - 1,
                   "%d: got wrong final_size %lu\n", i, final_size);
                ok(!memcmp(buf, test_lznt[i].uncompressed, test_lznt[i].uncompressed_size - 1),
                   "%d: got wrong decoded data\n", i);
                ok(buf[test_lznt[i].uncompressed_size - 1] == 0x11,
                   "%d: buf[%lu] was modified\n", i, test_lznt[i].uncompressed_size - 1);
            }
        }

        /* test with zero output size */
        final_size = 0xdeadbeef;
        memset(buf, 0x11, sizeof(buf));
        status = RtlDecompressBuffer(COMPRESSION_FORMAT_LZNT1, buf, 0, test_lznt[i].compressed,
                                     test_lznt[i].compressed_size, &final_size);
        if (is_incomplete_chunk(test_lznt[i].compressed, test_lznt[i].compressed_size, FALSE))
            ok(status == STATUS_BAD_COMPRESSION_BUFFER, "%d: got wrong status 0x%08lx\n", i, status);
        else
        {
            ok(status == STATUS_SUCCESS, "%d: got wrong status 0x%08lx\n", i, status);
            ok(final_size == 0, "%d: got wrong final_size %lu\n", i, final_size);
            ok(buf[0] == 0x11, "%d: buf[0] was modified\n", i);
        }

        /* test RtlDecompressFragment with offset = 0 */
        final_size = 0xdeadbeef;
        memset(buf, 0x11, sizeof(buf));
        status = RtlDecompressFragment(COMPRESSION_FORMAT_LZNT1, buf, sizeof(buf), test_lznt[i].compressed,
                                       test_lznt[i].compressed_size, 0, &final_size, workspace);
        if (test_lznt[i].broken_flags & DECOMPRESS_BROKEN_FRAGMENT)
            todo_wine
            ok(status == STATUS_BAD_COMPRESSION_BUFFER, "%d: got wrong status 0x%08lx\n", i, status);
        else
            ok(status == test_lznt[i].status, "%d: got wrong status 0x%08lx\n", i, status);
        if (!status)
        {
            ok(final_size == test_lznt[i].uncompressed_size,
               "%d: got wrong final_size %lu\n", i, final_size);
            ok(!memcmp(buf, test_lznt[i].uncompressed, test_lznt[i].uncompressed_size),
               "%d: got wrong decoded data\n", i);
            ok(buf[test_lznt[i].uncompressed_size] == 0x11,
               "%d: buf[%lu] was modified\n", i, test_lznt[i].uncompressed_size);
        }

        /* test RtlDecompressFragment with offset = 1 */
        final_size = 0xdeadbeef;
        memset(buf, 0x11, sizeof(buf));
        status = RtlDecompressFragment(COMPRESSION_FORMAT_LZNT1, buf, sizeof(buf), test_lznt[i].compressed,
                                       test_lznt[i].compressed_size, 1, &final_size, workspace);
        if (test_lznt[i].broken_flags & DECOMPRESS_BROKEN_FRAGMENT)
            todo_wine
            ok(status == STATUS_BAD_COMPRESSION_BUFFER, "%d: got wrong status 0x%08lx\n", i, status);
        else
            ok(status == test_lznt[i].status, "%d: got wrong status 0x%08lx\n", i, status);
        if (!status)
        {
            if (test_lznt[i].uncompressed_size == 0)
            {
                todo_wine
                ok(final_size == 4095, "%d: got wrong final_size %lu\n", i, final_size);
                /* Buffer doesn't contain any useful value on Windows */
                ok(buf[4095] == 0x11, "%d: buf[4095] was modified\n", i);
            }
            else
            {
                ok(final_size == test_lznt[i].uncompressed_size - 1,
                   "%d: got wrong final_size %lu\n", i, final_size);
                ok(!memcmp(buf, test_lznt[i].uncompressed + 1, test_lznt[i].uncompressed_size - 1),
                   "%d: got wrong decoded data\n", i);
                ok(buf[test_lznt[i].uncompressed_size - 1] == 0x11,
                   "%d: buf[%lu] was modified\n", i, test_lznt[i].uncompressed_size - 1);
            }
        }

        /* test RtlDecompressFragment with offset = 4095 */
        final_size = 0xdeadbeef;
        memset(buf, 0x11, sizeof(buf));
        status = RtlDecompressFragment(COMPRESSION_FORMAT_LZNT1, buf, sizeof(buf), test_lznt[i].compressed,
                                       test_lznt[i].compressed_size, 4095, &final_size, workspace);
        if (test_lznt[i].broken_flags & DECOMPRESS_BROKEN_FRAGMENT)
            todo_wine
            ok(status == STATUS_BAD_COMPRESSION_BUFFER, "%d: got wrong status 0x%08lx\n", i, status);
        else
            ok(status == test_lznt[i].status, "%d: got wrong status 0x%08lx\n", i, status);
        if (!status)
        {
            todo_wine
            ok(final_size == 1, "%d: got wrong final_size %lu\n", i, final_size);
            todo_wine
            ok(buf[0] == 0, "%d: padding is not zero\n", i);
            ok(buf[1] == 0x11, "%d: buf[1] was modified\n", i);
        }

        /* test RtlDecompressFragment with offset = 4096 */
        final_size = 0xdeadbeef;
        memset(buf, 0x11, sizeof(buf));
        status = RtlDecompressFragment(COMPRESSION_FORMAT_LZNT1, buf, sizeof(buf), test_lznt[i].compressed,
                                       test_lznt[i].compressed_size, 4096, &final_size, workspace);
        expected_status = is_incomplete_chunk(test_lznt[i].compressed, test_lznt[i].compressed_size, TRUE) ?
                          test_lznt[i].status : STATUS_SUCCESS;
        ok(status == expected_status, "%d: got wrong status 0x%08lx, expected 0x%08lx\n", i, status, expected_status);
        if (!status)
        {
            ok(final_size == 0, "%d: got wrong final_size %lu\n", i, final_size);
            ok(buf[0] == 0x11, "%d: buf[4096] was modified\n", i);
        }
    }
}

#undef DECOMPRESS_BROKEN_FRAGMENT
#undef DECOMPRESS_BROKEN_TRUNCATED

struct critsect_locked_info
{
    CRITICAL_SECTION crit;
    HANDLE semaphores[2];
};

static DWORD WINAPI critsect_locked_thread(void *param)
{
    struct critsect_locked_info *info = param;
    DWORD ret;

    ret = pRtlIsCriticalSectionLocked(&info->crit);
    ok(ret == TRUE, "expected TRUE, got %lu\n", ret);
    ret = pRtlIsCriticalSectionLockedByThread(&info->crit);
    ok(ret == FALSE, "expected FALSE, got %lu\n", ret);

    ReleaseSemaphore(info->semaphores[0], 1, NULL);
    ret = WaitForSingleObject(info->semaphores[1], 1000);
    ok(ret == WAIT_OBJECT_0, "expected WAIT_OBJECT_0, got %lu\n", ret);

    ret = pRtlIsCriticalSectionLocked(&info->crit);
    ok(ret == FALSE, "expected FALSE, got %lu\n", ret);
    ret = pRtlIsCriticalSectionLockedByThread(&info->crit);
    ok(ret == FALSE, "expected FALSE, got %lu\n", ret);

    EnterCriticalSection(&info->crit);

    ret = pRtlIsCriticalSectionLocked(&info->crit);
    ok(ret == TRUE, "expected TRUE, got %lu\n", ret);
    ret = pRtlIsCriticalSectionLockedByThread(&info->crit);
    ok(ret == TRUE, "expected TRUE, got %lu\n", ret);

    ReleaseSemaphore(info->semaphores[0], 1, NULL);
    ret = WaitForSingleObject(info->semaphores[1], 1000);
    ok(ret == WAIT_OBJECT_0, "expected WAIT_OBJECT_0, got %lu\n", ret);

    LeaveCriticalSection(&info->crit);
    return 0;
}

static void test_RtlIsCriticalSectionLocked(void)
{
    struct critsect_locked_info info;
    HANDLE thread;
    BOOL ret;

    if (!pRtlIsCriticalSectionLocked || !pRtlIsCriticalSectionLockedByThread)
    {
        win_skip("skipping RtlIsCriticalSectionLocked tests, required functions not available\n");
        return;
    }

    InitializeCriticalSection(&info.crit);
    info.semaphores[0] = CreateSemaphoreW(NULL, 0, 1, NULL);
    ok(info.semaphores[0] != NULL, "CreateSemaphore failed with %lu\n", GetLastError());
    info.semaphores[1] = CreateSemaphoreW(NULL, 0, 1, NULL);
    ok(info.semaphores[1] != NULL, "CreateSemaphore failed with %lu\n", GetLastError());

    ret = pRtlIsCriticalSectionLocked(&info.crit);
    ok(ret == FALSE, "expected FALSE, got %u\n", ret);
    ret = pRtlIsCriticalSectionLockedByThread(&info.crit);
    ok(ret == FALSE, "expected FALSE, got %u\n", ret);

    EnterCriticalSection(&info.crit);

    ret = pRtlIsCriticalSectionLocked(&info.crit);
    ok(ret == TRUE, "expected TRUE, got %u\n", ret);
    ret = pRtlIsCriticalSectionLockedByThread(&info.crit);
    ok(ret == TRUE, "expected TRUE, got %u\n", ret);

    thread = CreateThread(NULL, 0, critsect_locked_thread, &info, 0, NULL);
    ok(thread != NULL, "CreateThread failed with %lu\n", GetLastError());
    ret = WaitForSingleObject(info.semaphores[0], 1000);
    ok(ret == WAIT_OBJECT_0, "expected WAIT_OBJECT_0, got %u\n", ret);

    LeaveCriticalSection(&info.crit);

    ReleaseSemaphore(info.semaphores[1], 1, NULL);
    ret = WaitForSingleObject(info.semaphores[0], 1000);
    ok(ret == WAIT_OBJECT_0, "expected WAIT_OBJECT_0, got %u\n", ret);

    ret = pRtlIsCriticalSectionLocked(&info.crit);
    ok(ret == TRUE, "expected TRUE, got %u\n", ret);
    ret = pRtlIsCriticalSectionLockedByThread(&info.crit);
    ok(ret == FALSE, "expected FALSE, got %u\n", ret);

    ReleaseSemaphore(info.semaphores[1], 1, NULL);
    ret = WaitForSingleObject(thread, 1000);
    ok(ret == WAIT_OBJECT_0, "expected WAIT_OBJECT_0, got %u\n", ret);

    CloseHandle(thread);
    CloseHandle(info.semaphores[0]);
    CloseHandle(info.semaphores[1]);
    DeleteCriticalSection(&info.crit);
}

static void test_RtlInitializeCriticalSectionEx(void)
{
    static const CRITICAL_SECTION_DEBUG *no_debug = (void *)~(ULONG_PTR)0;
    CRITICAL_SECTION cs;

    if (!pRtlInitializeCriticalSectionEx)
    {
        win_skip("RtlInitializeCriticalSectionEx is not available\n");
        return;
    }

    memset(&cs, 0x11, sizeof(cs));
    pRtlInitializeCriticalSectionEx(&cs, 0, 0);
    ok(cs.DebugInfo == no_debug || broken(cs.DebugInfo != NULL && cs.DebugInfo != no_debug) /* < Win8 */,
       "expected DebugInfo != NULL and DebugInfo != ~0, got %p\n", cs.DebugInfo);
    ok(cs.LockCount == -1, "expected LockCount == -1, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == 0, "expected RecursionCount == 0, got %ld\n", cs.RecursionCount);
    ok(cs.LockSemaphore == NULL, "expected LockSemaphore == NULL, got %p\n", cs.LockSemaphore);
    ok(cs.SpinCount == 0 || broken(cs.SpinCount != 0) /* >= Win 8 */,
       "expected SpinCount == 0, got %Id\n", cs.SpinCount);
    RtlDeleteCriticalSection(&cs);

    memset(&cs, 0x11, sizeof(cs));
    pRtlInitializeCriticalSectionEx(&cs, 0, RTL_CRITICAL_SECTION_FLAG_NO_DEBUG_INFO);
    ok(cs.DebugInfo == no_debug, "expected DebugInfo == ~0, got %p\n", cs.DebugInfo);
    ok(cs.LockCount == -1, "expected LockCount == -1, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == 0, "expected RecursionCount == 0, got %ld\n", cs.RecursionCount);
    ok(cs.LockSemaphore == NULL, "expected LockSemaphore == NULL, got %p\n", cs.LockSemaphore);
    ok(cs.SpinCount == 0 || broken(cs.SpinCount != 0) /* >= Win 8 */,
       "expected SpinCount == 0, got %Id\n", cs.SpinCount);
    RtlDeleteCriticalSection(&cs);
}

static void test_RtlLeaveCriticalSection(void)
{
    RTL_CRITICAL_SECTION cs;
    NTSTATUS status;

    if (!pRtlInitializeCriticalSectionEx)
        return; /* Skip winxp */

    status = RtlInitializeCriticalSection(&cs);
    ok(!status, "RtlInitializeCriticalSection failed: %lx\n", status);

    status = RtlEnterCriticalSection(&cs);
    ok(!status, "RtlEnterCriticalSection failed: %lx\n", status);
    todo_wine
    ok(cs.LockCount == -2, "expected LockCount == -2, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == 1, "expected RecursionCount == 1, got %ld\n", cs.RecursionCount);
    ok(cs.OwningThread == ULongToHandle(GetCurrentThreadId()), "unexpected OwningThread\n");

    status = RtlLeaveCriticalSection(&cs);
    ok(!status, "RtlLeaveCriticalSection failed: %lx\n", status);
    ok(cs.LockCount == -1, "expected LockCount == -1, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == 0, "expected RecursionCount == 0, got %ld\n", cs.RecursionCount);
    ok(!cs.OwningThread, "unexpected OwningThread %p\n", cs.OwningThread);

    /*
     * Trying to leave a section that wasn't acquired modifies RecursionCount to an invalid value,
     * but doesn't modify LockCount so that an attempt to enter the section later will work.
     */
    status = RtlLeaveCriticalSection(&cs);
    ok(!status, "RtlLeaveCriticalSection failed: %lx\n", status);
    ok(cs.LockCount == -1, "expected LockCount == -1, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == -1, "expected RecursionCount == -1, got %ld\n", cs.RecursionCount);
    ok(!cs.OwningThread, "unexpected OwningThread %p\n", cs.OwningThread);

    /* and again */
    status = RtlLeaveCriticalSection(&cs);
    ok(!status, "RtlLeaveCriticalSection failed: %lx\n", status);
    ok(cs.LockCount == -1, "expected LockCount == -1, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == -2, "expected RecursionCount == -2, got %ld\n", cs.RecursionCount);
    ok(!cs.OwningThread, "unexpected OwningThread %p\n", cs.OwningThread);

    /* entering section fixes RecursionCount */
    status = RtlEnterCriticalSection(&cs);
    ok(!status, "RtlEnterCriticalSection failed: %lx\n", status);
    todo_wine
    ok(cs.LockCount == -2, "expected LockCount == -2, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == 1, "expected RecursionCount == 1, got %ld\n", cs.RecursionCount);
    ok(cs.OwningThread == ULongToHandle(GetCurrentThreadId()), "unexpected OwningThread\n");

    status = RtlLeaveCriticalSection(&cs);
    ok(!status, "RtlLeaveCriticalSection failed: %lx\n", status);
    ok(cs.LockCount == -1, "expected LockCount == -1, got %ld\n", cs.LockCount);
    ok(cs.RecursionCount == 0, "expected RecursionCount == 0, got %ld\n", cs.RecursionCount);
    ok(!cs.OwningThread, "unexpected OwningThread %p\n", cs.OwningThread);

    status = RtlDeleteCriticalSection(&cs);
    ok(!status, "RtlDeleteCriticalSection failed: %lx\n", status);
}

struct ldr_enum_context
{
    BOOL abort;
    BOOL found;
    int  count;
};

static void WINAPI ldr_enum_callback(LDR_DATA_TABLE_ENTRY *module, void *context, BOOLEAN *stop)
{
    static const WCHAR ntdllW[] = {'n','t','d','l','l','.','d','l','l',0};
    struct ldr_enum_context *ctx = context;

    if (!lstrcmpiW(module->BaseDllName.Buffer, ntdllW))
        ctx->found = TRUE;

    ctx->count++;
    *stop = ctx->abort;
}

static void test_LdrEnumerateLoadedModules(void)
{
    struct ldr_enum_context ctx;
    NTSTATUS status;

    if (!pLdrEnumerateLoadedModules)
    {
        win_skip("LdrEnumerateLoadedModules not available\n");
        return;
    }

    ctx.abort = FALSE;
    ctx.found = FALSE;
    ctx.count = 0;
    status = pLdrEnumerateLoadedModules(NULL, ldr_enum_callback, &ctx);
    ok(status == STATUS_SUCCESS, "LdrEnumerateLoadedModules failed with %08lx\n", status);
    ok(ctx.count > 1, "Expected more than one module, got %d\n", ctx.count);
    ok(ctx.found, "Could not find ntdll in list of modules\n");

    ctx.abort = TRUE;
    ctx.count = 0;
    status = pLdrEnumerateLoadedModules(NULL, ldr_enum_callback, &ctx);
    ok(status == STATUS_SUCCESS, "LdrEnumerateLoadedModules failed with %08lx\n", status);
    ok(ctx.count == 1, "Expected exactly one module, got %d\n", ctx.count);

    status = pLdrEnumerateLoadedModules((void *)0x1, ldr_enum_callback, (void *)0xdeadbeef);
    ok(status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got 0x%08lx\n", status);

    status = pLdrEnumerateLoadedModules((void *)0xdeadbeef, ldr_enum_callback, (void *)0xdeadbeef);
    ok(status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got 0x%08lx\n", status);

    status = pLdrEnumerateLoadedModules(NULL, NULL, (void *)0xdeadbeef);
    ok(status == STATUS_INVALID_PARAMETER, "expected STATUS_INVALID_PARAMETER, got 0x%08lx\n", status);
}

static void test_RtlMakeSelfRelativeSD(void)
{
    char buf[sizeof(SECURITY_DESCRIPTOR_RELATIVE) + 4];
    SECURITY_DESCRIPTOR_RELATIVE *sd_rel = (SECURITY_DESCRIPTOR_RELATIVE *)buf;
    SECURITY_DESCRIPTOR sd;
    NTSTATUS status;
    DWORD len;

    memset( &sd, 0, sizeof(sd) );
    sd.Revision = SECURITY_DESCRIPTOR_REVISION;

    len = 0;
    status = RtlMakeSelfRelativeSD( &sd, NULL, &len );
    ok( status == STATUS_BUFFER_TOO_SMALL, "got %08lx\n", status );
    ok( len == sizeof(*sd_rel), "got %lu\n", len );

    len += 4;
    status = RtlMakeSelfRelativeSD( &sd, sd_rel, &len );
    ok( status == STATUS_SUCCESS, "got %08lx\n", status );
    ok( len == sizeof(*sd_rel) + 4, "got %lu\n", len );

    len = 0;
    status = RtlAbsoluteToSelfRelativeSD( &sd, NULL, &len );
    ok( status == STATUS_BUFFER_TOO_SMALL, "got %08lx\n", status );
    ok( len == sizeof(*sd_rel), "got %lu\n", len );

    len += 4;
    status = RtlAbsoluteToSelfRelativeSD( &sd, sd_rel, &len );
    ok( status == STATUS_SUCCESS, "got %08lx\n", status );
    ok( len == sizeof(*sd_rel) + 4, "got %lu\n", len );

    sd.Control = SE_SELF_RELATIVE;
    status = RtlMakeSelfRelativeSD( &sd, sd_rel, &len );
    ok( status == STATUS_SUCCESS, "got %08lx\n", status );
    ok( len == sizeof(*sd_rel) + 4, "got %lu\n", len );

    status = RtlAbsoluteToSelfRelativeSD( &sd, sd_rel, &len );
    ok( status == STATUS_BAD_DESCRIPTOR_FORMAT, "got %08lx\n", status );
}

static DWORD (CALLBACK *orig_entry)(HMODULE,DWORD,LPVOID);
static DWORD *dll_main_data;

static inline void *get_rva( HMODULE module, DWORD va )
{
    return (void *)((char *)module + va);
}

static void CALLBACK ldr_notify_callback1(ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, void *context)
{
    const IMAGE_IMPORT_DESCRIPTOR *imports;
    const IMAGE_THUNK_DATA *import_list;
    IMAGE_THUNK_DATA *thunk_list;
    LDR_DATA_TABLE_ENTRY *mod;
    DWORD *calls = context;
    LIST_ENTRY *mark;
    ULONG size;
    int i, j;

    *calls <<= 4;
    *calls |= reason;

    if (!lstrcmpiW(data->Loaded.BaseDllName->Buffer, expected_dll))
        return;

    ok(data->Loaded.Flags == 0, "Expected flags 0, got %lx\n", data->Loaded.Flags);
    ok(!lstrcmpiW(data->Loaded.BaseDllName->Buffer, expected_dll), "Expected %s, got %s\n",
       wine_dbgstr_w(expected_dll), wine_dbgstr_w(data->Loaded.BaseDllName->Buffer));
    ok(!!data->Loaded.DllBase, "Expected non zero base address\n");
    ok(data->Loaded.SizeOfImage, "Expected non zero image size\n");

    /* expect module to be last module listed in LdrData load order list */
    mark = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;
    mod = CONTAINING_RECORD(mark->Blink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    ok(mod->DllBase == data->Loaded.DllBase, "Expected base address %p, got %p\n",
       data->Loaded.DllBase, mod->DllBase);
    ok(!lstrcmpiW(mod->BaseDllName.Buffer, expected_dll), "Expected %s, got %s\n",
       wine_dbgstr_w(expected_dll), wine_dbgstr_w(mod->BaseDllName.Buffer));

    /* show that imports have already been resolved */
    imports = RtlImageDirectoryEntryToData(data->Loaded.DllBase, TRUE, IMAGE_DIRECTORY_ENTRY_IMPORT, &size);
    ok(!!imports, "Expected dll to have imports\n");

    for (i = 0; imports[i].Name; i++)
    {
        thunk_list = get_rva(data->Loaded.DllBase, (DWORD)imports[i].FirstThunk);
        if (imports[i].OriginalFirstThunk)
            import_list = get_rva(data->Loaded.DllBase, (DWORD)imports[i].OriginalFirstThunk);
        else
            import_list = thunk_list;

        for (j = 0; import_list[j].u1.Ordinal; j++)
        {
            ok(thunk_list[j].u1.AddressOfData > data->Loaded.SizeOfImage,
               "Import has not been resolved: %p\n", (void*)thunk_list[j].u1.Function);
        }
    }
}

static void CALLBACK ldr_notify_callback2(ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, void *context)
{
    DWORD *calls = context;
    *calls <<= 4;
    *calls |= reason + 2;
}

static BOOL WINAPI fake_dll_main(HINSTANCE instance, DWORD reason, void* reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        *dll_main_data <<= 4;
        *dll_main_data |= 3;
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        *dll_main_data <<= 4;
        *dll_main_data |= 4;
    }
    return orig_entry(instance, reason, reserved);
}

static void CALLBACK ldr_notify_callback_dll_main(ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, void *context)
{
    DWORD *calls = context;
    LIST_ENTRY *mark;
    LDR_DATA_TABLE_ENTRY *mod;

    *calls <<= 4;
    *calls |= reason;

    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;

    mark = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;
    mod = CONTAINING_RECORD(mark->Blink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    ok(mod->DllBase == data->Loaded.DllBase, "Expected base address %p, got %p\n",
       data->Loaded.DllBase, mod->DllBase);
    if (mod->DllBase != data->Loaded.DllBase)
       return;

    orig_entry = mod->EntryPoint;
    mod->EntryPoint = fake_dll_main;
    dll_main_data = calls;
}

static BOOL WINAPI fake_dll_main_fail(HINSTANCE instance, DWORD reason, void* reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        *dll_main_data <<= 4;
        *dll_main_data |= 3;
    }
    else if (reason == DLL_PROCESS_DETACH)
    {
        *dll_main_data <<= 4;
        *dll_main_data |= 4;
    }
    return FALSE;
}

static void CALLBACK ldr_notify_callback_fail(ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, void *context)
{
    DWORD *calls = context;
    LIST_ENTRY *mark;
    LDR_DATA_TABLE_ENTRY *mod;

    *calls <<= 4;
    *calls |= reason;

    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;

    mark = &NtCurrentTeb()->Peb->LdrData->InMemoryOrderModuleList;
    mod = CONTAINING_RECORD(mark->Blink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
    ok(mod->DllBase == data->Loaded.DllBase, "Expected base address %p, got %p\n",
       data->Loaded.DllBase, mod->DllBase);
    if (mod->DllBase != data->Loaded.DllBase)
       return;

    orig_entry = mod->EntryPoint;
    mod->EntryPoint = fake_dll_main_fail;
    dll_main_data = calls;
}

static void CALLBACK ldr_notify_callback_imports(ULONG reason, LDR_DLL_NOTIFICATION_DATA *data, void *context)
{
    DWORD *calls = context;

    if (reason != LDR_DLL_NOTIFICATION_REASON_LOADED)
        return;

    if (!lstrcmpiW(data->Loaded.BaseDllName->Buffer, crypt32dllW))
    {
        *calls <<= 4;
        *calls |= 1;
    }

    if (!lstrcmpiW(data->Loaded.BaseDllName->Buffer, wintrustdllW))
    {
        *calls <<= 4;
        *calls |= 2;
    }
}

static void test_LdrRegisterDllNotification(void)
{
    void *cookie, *cookie2;
    NTSTATUS status;
    HMODULE mod;
    DWORD calls;

    if (!pLdrRegisterDllNotification || !pLdrUnregisterDllNotification)
    {
        win_skip("Ldr(Un)RegisterDllNotification not available\n");
        return;
    }

    mod = LoadLibraryW(expected_dll);
    if(mod)
        FreeLibrary(mod);
    else
        expected_dll = ws2_32dllW; /* XP Default */

    /* generic test */
    status = pLdrRegisterDllNotification(0, ldr_notify_callback1, &calls, &cookie);
    ok(!status, "Expected STATUS_SUCCESS, got %08lx\n", status);

    calls = 0;
    mod = LoadLibraryW(expected_dll);
    ok(!!mod, "Failed to load library: %ld\n", GetLastError());
    ok(calls == LDR_DLL_NOTIFICATION_REASON_LOADED, "Expected LDR_DLL_NOTIFICATION_REASON_LOADED, got %lx\n", calls);

    calls = 0;
    FreeLibrary(mod);
    ok(calls == LDR_DLL_NOTIFICATION_REASON_UNLOADED, "Expected LDR_DLL_NOTIFICATION_REASON_UNLOADED, got %lx\n", calls);

    /* test order of callbacks */
    status = pLdrRegisterDllNotification(0, ldr_notify_callback2, &calls, &cookie2);
    ok(!status, "Expected STATUS_SUCCESS, got %08lx\n", status);

    calls = 0;
    mod = LoadLibraryW(expected_dll);
    ok(!!mod, "Failed to load library: %ld\n", GetLastError());
    ok(calls == 0x13, "Expected order 0x13, got %lx\n", calls);

    calls = 0;
    FreeLibrary(mod);
    ok(calls == 0x24, "Expected order 0x24, got %lx\n", calls);

    pLdrUnregisterDllNotification(cookie2);
    pLdrUnregisterDllNotification(cookie);

    /* test dll main order */
    status = pLdrRegisterDllNotification(0, ldr_notify_callback_dll_main, &calls, &cookie);
    ok(!status, "Expected STATUS_SUCCESS, got %08lx\n", status);

    calls = 0;
    mod = LoadLibraryW(expected_dll);
    ok(!!mod, "Failed to load library: %ld\n", GetLastError());
    ok(calls == 0x13, "Expected order 0x13, got %lx\n", calls);

    calls = 0;
    FreeLibrary(mod);
    ok(calls == 0x42, "Expected order 0x42, got %lx\n", calls);

    pLdrUnregisterDllNotification(cookie);

    /* test dll main order */
    status = pLdrRegisterDllNotification(0, ldr_notify_callback_fail, &calls, &cookie);
    ok(!status, "Expected STATUS_SUCCESS, got %08lx\n", status);

    calls = 0;
    mod = LoadLibraryW(expected_dll);
    ok(!mod, "Expected library to fail loading\n");
    ok(calls == 0x1342, "Expected order 0x1342, got %lx\n", calls);

    pLdrUnregisterDllNotification(cookie);

    /* test dll with dependencies */
    status = pLdrRegisterDllNotification(0, ldr_notify_callback_imports, &calls, &cookie);
    ok(!status, "Expected STATUS_SUCCESS, got %08lx\n", status);

    calls = 0;
    mod = LoadLibraryW(wintrustdllW);
    ok(!!mod, "Failed to load library: %ld\n", GetLastError());
    ok(calls == 0x12 || calls == 0x21, "got %lx\n", calls);

    FreeLibrary(mod);
    pLdrUnregisterDllNotification(cookie);
}

static BOOL test_dbg_print_except;
static LONG test_dbg_print_except_ret;

static LONG CALLBACK test_dbg_print_except_handler( EXCEPTION_POINTERS *eptrs )
{
    if (eptrs->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C)
    {
        ok( eptrs->ExceptionRecord->NumberParameters == 2,
            "Unexpected NumberParameters: %ld\n", eptrs->ExceptionRecord->NumberParameters );
        ok( eptrs->ExceptionRecord->ExceptionInformation[0] == strlen("test_DbgPrint: Hello World") + 1,
            "Unexpected ExceptionInformation[0]: %d\n", (int)eptrs->ExceptionRecord->ExceptionInformation[0] );
        ok( !strcmp((char *)eptrs->ExceptionRecord->ExceptionInformation[1], "test_DbgPrint: Hello World"),
            "Unexpected ExceptionInformation[1]: %s\n", wine_dbgstr_a((char *)eptrs->ExceptionRecord->ExceptionInformation[1]) );
        test_dbg_print_except = TRUE;
        return test_dbg_print_except_ret;
    }

    return (LONG)EXCEPTION_CONTINUE_SEARCH;
}

static NTSTATUS WINAPIV test_vDbgPrintEx( ULONG id, ULONG level, const char *fmt, ... )
{
    NTSTATUS status;
    va_list args;
    va_start( args, fmt );
    status = vDbgPrintEx( id, level, fmt, args );
    va_end( args );
    return status;
}

static NTSTATUS WINAPIV test_vDbgPrintExWithPrefix( const char *prefix, ULONG id, ULONG level, const char *fmt, ... )
{
    NTSTATUS status;
    va_list args;
    va_start( args, fmt );
    status = vDbgPrintExWithPrefix( prefix, id, level, fmt, args );
    va_end( args );
    return status;
}

static void test_DbgPrint(void)
{
    NTSTATUS status;
    void *handler = RtlAddVectoredExceptionHandler( TRUE, test_dbg_print_except_handler );
    PEB *Peb = NtCurrentTeb()->Peb;
    BOOL debugged = Peb->BeingDebugged;

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = DbgPrint( "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrint returned %lx\n", status );
    ok( !test_dbg_print_except, "DBG_PRINTEXCEPTION_C received\n" );

    Peb->BeingDebugged = TRUE;
    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = DbgPrint( "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrint returned %lx\n", status );
    ok( test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_CONTINUE_EXECUTION;
    status = DbgPrint( "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrint returned %lx\n", status );
    ok( test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_CONTINUE_SEARCH;
    status = DbgPrint( "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrint returned %lx\n", status );
    ok( test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );


    /* FIXME: NtSetDebugFilterState / DbgSetDebugFilterState are probably what's controlling these */

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = DbgPrintEx( 0, DPFLTR_ERROR_LEVEL, "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrintEx returned %lx\n", status );
    ok( test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = DbgPrintEx( 0, DPFLTR_WARNING_LEVEL, "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrintEx returned %lx\n", status );
    ok( !test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = DbgPrintEx( 0, DPFLTR_MASK|(1 << DPFLTR_ERROR_LEVEL), "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrintEx returned %lx\n", status );
    ok( test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = DbgPrintEx( 0, DPFLTR_MASK|(1 << DPFLTR_WARNING_LEVEL), "test_DbgPrint: %s", "Hello World" );
    ok( !status, "DbgPrintEx returned %lx\n", status );
    ok( !test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );


    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = test_vDbgPrintEx( 0, 0xFFFFFFFF, "test_DbgPrint: %s", "Hello World" );
    ok( !status, "vDbgPrintEx returned %lx\n", status );
    ok( test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );

    test_dbg_print_except = FALSE;
    test_dbg_print_except_ret = (LONG)EXCEPTION_EXECUTE_HANDLER;
    status = test_vDbgPrintExWithPrefix( "test_", 0, 0xFFFFFFFF, "DbgPrint: %s", "Hello World" );
    ok( !status, "vDbgPrintExWithPrefix returned %lx\n", status );
    ok( test_dbg_print_except, "DBG_PRINTEXCEPTION_C not received\n" );

    Peb->BeingDebugged = debugged;
    RtlRemoveVectoredExceptionHandler( handler );
}

static BOOL test_heap_destroy_dbgstr = FALSE;
static BOOL test_heap_destroy_break = FALSE;

static LONG CALLBACK test_heap_destroy_except_handler( EXCEPTION_POINTERS *eptrs )
{
    if (eptrs->ExceptionRecord->ExceptionCode == STATUS_BREAKPOINT)
    {
#if defined( __i386__ )
        eptrs->ContextRecord->Eip += 1;
        test_heap_destroy_break = TRUE;
        return (LONG)EXCEPTION_CONTINUE_EXECUTION;
#elif defined( __x86_64__ )
        eptrs->ContextRecord->Rip += 1;
        test_heap_destroy_break = TRUE;
        return (LONG)EXCEPTION_CONTINUE_EXECUTION;
#elif defined( __aarch64__ )
        eptrs->ContextRecord->Pc += 4;
        test_heap_destroy_break = TRUE;
        return (LONG)EXCEPTION_CONTINUE_EXECUTION;
#endif
    }

    if (eptrs->ExceptionRecord->ExceptionCode == DBG_PRINTEXCEPTION_C)
    {
        test_heap_destroy_dbgstr = TRUE;
        return (LONG)EXCEPTION_CONTINUE_EXECUTION;
    }

    return (LONG)EXCEPTION_CONTINUE_SEARCH;
}

/* partially copied from ntdll/heap.c */
#define HEAP_VALIDATE_PARAMS 0x40000000

struct heap
{
    DWORD_PTR unknown1[2];
    DWORD     unknown2[2];
    DWORD_PTR unknown3[4];
    DWORD     unknown4;
    DWORD_PTR unknown5[2];
    DWORD     unknown6[3];
    DWORD_PTR unknown7[2];
    DWORD     flags;
    DWORD     force_flags;
    DWORD_PTR unknown8[6];
};

static void test_RtlDestroyHeap(void)
{
    const struct heap invalid = {{0, 0}, {0, HEAP_VALIDATE_PARAMS}, {0, 0, 0, 0}, 0, {0, 0}, {0, 0, 0}, {0, 0}, HEAP_VALIDATE_PARAMS, 0, {0}};
    HANDLE heap = (HANDLE)&invalid, ret;
    PEB *Peb = NtCurrentTeb()->Peb;
    BOOL debugged;
    void *handler = RtlAddVectoredExceptionHandler( TRUE, test_heap_destroy_except_handler );

    test_heap_destroy_dbgstr = FALSE;
    test_heap_destroy_break = FALSE;
    debugged = Peb->BeingDebugged;
    Peb->BeingDebugged = TRUE;
    ret = RtlDestroyHeap( heap );
    ok( ret == heap, "RtlDestroyHeap(%p) returned %p\n", heap, ret );
    ok( test_heap_destroy_dbgstr, "HeapDestroy didn't call OutputDebugStrA\n" );
    ok( test_heap_destroy_break, "HeapDestroy didn't call DbgBreakPoint\n" );
    Peb->BeingDebugged = debugged;

    RtlRemoveVectoredExceptionHandler( handler );
}

struct commit_routine_context
{
    void *base;
    SIZE_T size;
};

static struct commit_routine_context commit_context;

static NTSTATUS NTAPI test_commit_routine(void *base, void **address, SIZE_T *size)
{
    commit_context.base = base;
    commit_context.size = *size;

    return VirtualAlloc(*address, *size, MEM_COMMIT, PAGE_READWRITE) ? 0 : STATUS_ASSERTION_FAILURE;
}

static void test_RtlCreateHeap(void)
{
    void *ptr, *base, *reserve;
    RTL_HEAP_PARAMETERS params;
    HANDLE heap;
    BOOL ret;

    heap = RtlCreateHeap(0, NULL, 0, 0, NULL, NULL);
    ok(!!heap, "Failed to create a heap.\n");
    RtlDestroyHeap(heap);

    memset(&params, 0, sizeof(params));
    heap = RtlCreateHeap(0, NULL, 0, 0, NULL, &params);
    ok(!!heap, "Failed to create a heap.\n");
    RtlDestroyHeap(heap);

    params.Length = 1;
    heap = RtlCreateHeap(0, NULL, 0, 0, NULL, &params);
    ok(!!heap, "Failed to create a heap.\n");
    RtlDestroyHeap(heap);

    params.Length = sizeof(params);
    params.CommitRoutine = test_commit_routine;
    params.InitialCommit = 0x1000;
    params.InitialReserve = 0x10000;

    heap = RtlCreateHeap(0, NULL, 0, 0, NULL, &params);
    todo_wine
    ok(!heap, "Unexpected heap.\n");
    if (heap)
        RtlDestroyHeap(heap);

    reserve = VirtualAlloc(NULL, 0x10000, MEM_RESERVE, PAGE_READWRITE);
    base = VirtualAlloc(reserve, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    ok(!!base, "Unexpected pointer.\n");

    heap = RtlCreateHeap(0, base, 0, 0, NULL, &params);
    ok(!!heap, "Unexpected heap.\n");

    /* Using block size above initially committed size to trigger
       new allocation via user callback. */
    ptr = RtlAllocateHeap(heap, 0, 0x4000);
    ok(!!ptr, "Failed to allocate a block.\n");
    todo_wine
    ok(commit_context.base == base, "Unexpected base %p.\n", commit_context.base);
    todo_wine
    ok(!!commit_context.size, "Unexpected allocation size.\n");
    RtlFreeHeap(heap, 0, ptr);
    RtlDestroyHeap(heap);

    ret = VirtualFree(reserve, 0, MEM_RELEASE);
    todo_wine
    ok(ret, "Unexpected return value.\n");
}

static void test_RtlFirstFreeAce(void)
{
    PACL acl;
    PACE_HEADER first;
    BOOL ret;
    DWORD size;
    BOOLEAN found;

    size = sizeof(ACL) + (sizeof(ACCESS_ALLOWED_ACE));
    acl = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, size);
    ret = InitializeAcl(acl, sizeof(ACL), ACL_REVISION);
    ok(ret, "InitializeAcl failed with error %ld\n", GetLastError());

    /* AceCount = 0 */
    first = (ACE_HEADER *)0xdeadbeef;
    found = RtlFirstFreeAce(acl, &first);
    ok(found, "RtlFirstFreeAce failed\n");
    ok(first == (PACE_HEADER)(acl + 1), "Failed to find ACL\n");

    acl->AclSize = sizeof(ACL) - 1;
    first = (ACE_HEADER *)0xdeadbeef;
    found = RtlFirstFreeAce(acl, &first);
    ok(found, "RtlFirstFreeAce failed\n");
    ok(first == NULL, "Found FirstAce = %p\n", first);

    /* AceCount = 1 */
    acl->AceCount = 1;
    acl->AclSize = size;
    first = (ACE_HEADER *)0xdeadbeef;
    found = RtlFirstFreeAce(acl, &first);
    ok(found, "RtlFirstFreeAce failed\n");
    ok(first == (PACE_HEADER)(acl + 1), "Failed to find ACL %p, %p\n", first, (PACE_HEADER)(acl + 1));

    acl->AclSize = sizeof(ACL) - 1;
    first = (ACE_HEADER *)0xdeadbeef;
    found = RtlFirstFreeAce(acl, &first);
    ok(!found, "RtlFirstFreeAce failed\n");
    ok(first == NULL, "Found FirstAce = %p\n", first);

    acl->AclSize = sizeof(ACL);
    first = (ACE_HEADER *)0xdeadbeef;
    found = RtlFirstFreeAce(acl, &first);
    ok(!found, "RtlFirstFreeAce failed\n");
    ok(first == NULL, "Found FirstAce = %p\n", first);

    HeapFree(GetProcessHeap(), 0, acl);
}

static void test_RtlGetAcesBufferSize(void)
{
    BYTE buffer[sizeof(ACL) + 16];
    ACE_HEADER *first, *second;
    ACL *acl = (ACL *)buffer;
    ULONG size;
    NTSTATUS status;

    if (!pRtlGetAcesBufferSize)
    {
        win_skip("RtlGetAcesBufferSize is unavailable.\n");
        return;
    }

    memset(buffer, 0, sizeof(buffer));
    acl->AclRevision = ACL_REVISION;
    acl->AclSize = sizeof(buffer);

    size = 0xdeadbeef;
    status = pRtlGetAcesBufferSize(acl, &size);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ok(size == 0, "Got size %lu.\n", size);

    first = (ACE_HEADER *)(acl + 1);
    first->AceSize = 4;
    second = (ACE_HEADER *)((BYTE *)first + first->AceSize);
    second->AceSize = 12;
    acl->AceCount = 2;
    size = 0xdeadbeef;
    status = pRtlGetAcesBufferSize(acl, &size);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ok(size == 16, "Got size %lu.\n", size);

    size = 0xdeadbeef;
    status = pRtlGetAcesBufferSize(NULL, &size);
    ok(status == STATUS_INVALID_PARAMETER, "Got status %#lx.\n", status);
    ok(size == 0xdeadbeef, "Got size %#lx.\n", size);

    status = pRtlGetAcesBufferSize(acl, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "Got status %#lx.\n", status);
}

static void test_RtlInitializeSid(void)
{
    SID_IDENTIFIER_AUTHORITY sid_ident = { SECURITY_NT_AUTHORITY };
    char buffer[SECURITY_MAX_SID_SIZE];
    PSID sid = (PSID)&buffer;
    NTSTATUS status;

    status = RtlInitializeSid(sid, &sid_ident, 1);
    ok(!status, "Unexpected status %#lx.\n", status);

    status = RtlInitializeSid(sid, &sid_ident, SID_MAX_SUB_AUTHORITIES);
    ok(!status, "Unexpected status %#lx.\n", status);

    status = RtlInitializeSid(sid, &sid_ident, SID_MAX_SUB_AUTHORITIES + 1);
    ok(status == STATUS_INVALID_PARAMETER, "Unexpected status %#lx.\n", status);
}

static void test_RtlCopySid(void)
{
    SID_IDENTIFIER_AUTHORITY sid_ident = { SECURITY_NT_AUTHORITY };
    char src_buffer[SECURITY_MAX_SID_SIZE], dst_buffer[SECURITY_MAX_SID_SIZE];
    PSID src = (PSID)&src_buffer, dst = (PSID)&dst_buffer;
    NTSTATUS status;

    status = RtlInitializeSid(src, &sid_ident, 1);
    ok(!status, "Unexpected status %#lx.\n", status);
    *RtlSubAuthoritySid(src, 0) = SECURITY_LOCAL_SYSTEM_RID;

    status = RtlCopySid(RtlLengthSid(src), dst, src);
    ok(!status, "Unexpected status %#lx.\n", status);
    ok(!memcmp(src, dst, RtlLengthSid(src)), "Copied SID doesn't match.\n");

    status = RtlCopySid(RtlLengthSid(src) - 1, dst, src);
    ok(status == STATUS_BUFFER_TOO_SMALL, "Unexpected status %#lx.\n", status);
}

static void test_RtlSidHash(void)
{
    SID_IDENTIFIER_AUTHORITY authority = { SECURITY_NT_AUTHORITY };
    SID_AND_ATTRIBUTES_HASH hash, expected;
    SID_AND_ATTRIBUTES attrs[66], *ret;
    SID sids[66], missing;
    ULONG hash_count, i;
    NTSTATUS status;

    if (!pRtlSidHashInitialize || !pRtlSidHashLookup)
    {
        win_skip("SID hash functions are unavailable.\n");
        return;
    }

    status = pRtlSidHashInitialize(NULL, 0, NULL);
    ok(status == STATUS_INVALID_PARAMETER, "Got status %#lx.\n", status);

    memset(&hash, 0xcc, sizeof(hash));
    status = pRtlSidHashInitialize(NULL, ARRAY_SIZE(attrs), &hash);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    memset(&expected, 0, sizeof(expected));
    ok(!memcmp(&hash, &expected, sizeof(hash)), "Hash was not cleared.\n");

    memset(sids, 0, sizeof(sids));
    memset(attrs, 0, sizeof(attrs));
    for (i = 0; i < ARRAY_SIZE(sids); i++)
    {
        status = RtlInitializeSid(&sids[i], &authority, 1);
        ok(status == STATUS_SUCCESS, "Got status %#lx for SID %lu.\n", status, i);
        sids[i].SubAuthority[0] = 0x100 + i;
        attrs[i].Sid = &sids[i];
        attrs[i].Attributes = 0x200 + i;
    }

    memset(&hash, 0xcc, sizeof(hash));
    status = pRtlSidHashInitialize(attrs, ARRAY_SIZE(attrs), &hash);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ok(hash.SidCount == ARRAY_SIZE(attrs), "Got SID count %lu.\n", hash.SidCount);
    ok(hash.SidAttr == attrs, "Got SID array %p.\n", hash.SidAttr);

    memset(&expected, 0, sizeof(expected));
    expected.SidCount = ARRAY_SIZE(attrs);
    expected.SidAttr = attrs;
    hash_count = min(ARRAY_SIZE(attrs), 8 * sizeof(expected.Hash[0]));
    for (i = 0; i < hash_count; i++)
    {
        BYTE value = sids[i].SubAuthority[0];
        SID_HASH_ENTRY bit = (SID_HASH_ENTRY)1 << i;

        expected.Hash[value & 0x0f] |= bit;
        expected.Hash[16 + (value >> 4)] |= bit;
    }
    ok(!memcmp(&hash, &expected, sizeof(hash)), "Got unexpected hash contents.\n");

    ret = pRtlSidHashLookup(&hash, &sids[0]);
    ok(ret == &attrs[0], "Got entry %p, expected %p.\n", ret, &attrs[0]);
    ret = pRtlSidHashLookup(&hash, &sids[hash_count / 2]);
    ok(ret == &attrs[hash_count / 2], "Got entry %p, expected %p.\n",
       ret, &attrs[hash_count / 2]);
    ret = pRtlSidHashLookup(&hash, &sids[hash_count - 1]);
    ok(ret == &attrs[hash_count - 1], "Got entry %p, expected %p.\n",
       ret, &attrs[hash_count - 1]);
    ret = pRtlSidHashLookup(&hash, &sids[hash_count + 1]);
    ok(ret == &attrs[hash_count + 1], "Got entry %p, expected %p.\n",
       ret, &attrs[hash_count + 1]);

    status = RtlInitializeSid(&missing, &authority, 1);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    missing.SubAuthority[0] = 0xff;
    ok(!pRtlSidHashLookup(&hash, &missing), "Found missing SID.\n");
    ok(!pRtlSidHashLookup(NULL, &sids[0]), "Lookup accepted a NULL hash.\n");
    ok(!pRtlSidHashLookup(&hash, NULL), "Lookup accepted a NULL SID.\n");

    attrs[1].Sid = attrs[0].Sid;
    status = pRtlSidHashInitialize(attrs, ARRAY_SIZE(attrs), &hash);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ret = pRtlSidHashLookup(&hash, attrs[0].Sid);
    ok(ret == &attrs[0], "Duplicate lookup returned %p, expected %p.\n", ret, &attrs[0]);
}

static void test_RtlValidSecurityDescriptor(void)
{
    SECURITY_DESCRIPTOR *sd;
    NTSTATUS status;
    BOOLEAN ret;

    ret = RtlValidSecurityDescriptor(NULL);
    ok(!ret, "Unexpected return value %d.\n", ret);

    sd = calloc(1, SECURITY_DESCRIPTOR_MIN_LENGTH);

    ret = RtlValidSecurityDescriptor(sd);
    ok(!ret, "Unexpected return value %d.\n", ret);

    status = RtlCreateSecurityDescriptor(sd, SECURITY_DESCRIPTOR_REVISION);
    ok(!status, "Unexpected return value %#lx.\n", status);

    ret = RtlValidSecurityDescriptor(sd);
    ok(ret, "Unexpected return value %d.\n", ret);

    free(sd);
}

static void test_RtlValidRelativeSecurityDescriptor(void)
{
    static const ULONG invalid_offsets[] = {1, 16, 19, 21, 31, 32, 0xfffffffc, 0xffffffff};
    static const SECURITY_INFORMATION required[] = {0, OWNER_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION,
        DACL_SECURITY_INFORMATION, SACL_SECURITY_INFORMATION, 0xffffffff};
    union { SECURITY_DESCRIPTOR_RELATIVE sd; BYTE bytes[128]; } buffer;
    SECURITY_DESCRIPTOR_RELATIVE *sd = &buffer.sd;
    BYTE *pages, *end, *copy;
    SYSTEM_INFO system_info;
    DWORD old_protect;
    SID *sid = (SID *)(buffer.bytes + sizeof(*sd));
    ACL *acl = (ACL *)(buffer.bytes + sizeof(*sd));
    ULONG *field;
    unsigned int i, j;
    BOOLEAN ret;

    memset(&buffer, 0, sizeof(buffer));
    sd->Revision = SECURITY_DESCRIPTOR_REVISION;
    sd->Control = SE_SELF_RELATIVE;

    for (i = 0; i <= sizeof(*sd); ++i)
    {
        ret = RtlValidRelativeSecurityDescriptor(sd, i, 0);
        ok(ret == (i == sizeof(*sd)), "Length %u: got %u.\n", i, ret);
    }
    for (i = 0; i < ARRAY_SIZE(required); ++i)
    {
        ret = RtlValidRelativeSecurityDescriptor(sd, sizeof(*sd), required[i]);
        ok(ret == !(required[i] & (OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION)),
           "Required %#lx: got %u.\n", required[i], ret);
    }
    sd->Control = 0;
    ok(!RtlValidRelativeSecurityDescriptor(sd, sizeof(*sd), 0), "Accepted an absolute descriptor.\n");
    sd->Control = SE_SELF_RELATIVE;
    sd->Revision = 0;
    ok(!RtlValidRelativeSecurityDescriptor(sd, sizeof(*sd), 0), "Accepted revision zero.\n");
    sd->Revision = SECURITY_DESCRIPTOR_REVISION;

    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = 1;
    for (i = 0; i < 2; ++i)
    {
        field = i ? &sd->Group : &sd->Owner;
        for (j = 0; j < ARRAY_SIZE(invalid_offsets); ++j)
        {
            *field = invalid_offsets[j];
            ret = RtlValidRelativeSecurityDescriptor(sd, 32, 0);
            ok(!ret, "SID field %u offset %#lx accepted.\n", i, *field);
        }
        *field = sizeof(*sd);
        for (j = 20; j <= 32; ++j)
        {
            ret = RtlValidRelativeSecurityDescriptor(sd, j, i ? GROUP_SECURITY_INFORMATION : OWNER_SECURITY_INFORMATION);
            ok(ret == (j == 32), "SID field %u length %u: got %u.\n", i, j, ret);
        }
        sid->Revision = 0;
        ok(!RtlValidRelativeSecurityDescriptor(sd, 32, 0), "Accepted invalid SID revision.\n");
        sid->Revision = SID_REVISION;
        sid->SubAuthorityCount = 16;
        ok(!RtlValidRelativeSecurityDescriptor(sd, sizeof(buffer), 0), "Accepted 16 SID subauthorities.\n");
        sid->SubAuthorityCount = 15;
        ok(RtlValidRelativeSecurityDescriptor(sd, 88, 0), "Rejected maximum SID.\n");
        ok(!RtlValidRelativeSecurityDescriptor(sd, 87, 0), "Accepted truncated maximum SID.\n");
        sid->SubAuthorityCount = 0;
        ok(!RtlValidRelativeSecurityDescriptor(sd, 28, 0), "Accepted SID without minimum descriptor space.\n");
        ok(RtlValidRelativeSecurityDescriptor(sd, 32, 0), "Rejected zero-subauthority SID with space.\n");
        sid->SubAuthorityCount = 1;
        *field = 0;
    }
    /* Owner and group may share the same SID. */
    sd->Owner = sd->Group = sizeof(*sd);
    ok(RtlValidRelativeSecurityDescriptor(sd, 32, OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION),
       "Rejected overlapping owner/group.\n");
    sd->Owner = sd->Group = 0;

    memset(acl, 0, sizeof(*acl));
    acl->AclRevision = ACL_REVISION;
    acl->AclSize = sizeof(*acl);
    for (i = 0; i < 2; ++i)
    {
        SECURITY_DESCRIPTOR_CONTROL present = i ? SE_SACL_PRESENT : SE_DACL_PRESENT;
        field = i ? &sd->Sacl : &sd->Dacl;
        *field = 0xffffffff;
        ok(RtlValidRelativeSecurityDescriptor(sd, sizeof(*sd), required[i + 3]),
           "Validated an absent ACL offset.\n");
        sd->Control |= present;
        *field = 0;
        ok(RtlValidRelativeSecurityDescriptor(sd, sizeof(*sd), required[i + 3]), "Rejected null ACL.\n");
        for (j = 0; j < ARRAY_SIZE(invalid_offsets); ++j)
        {
            *field = invalid_offsets[j];
            ok(!RtlValidRelativeSecurityDescriptor(sd, 28, 0), "ACL field %u offset %#lx accepted.\n", i, *field);
        }
        *field = sizeof(*sd);
        for (j = 20; j <= 28; ++j)
        {
            ret = RtlValidRelativeSecurityDescriptor(sd, j, 0);
            ok(ret == (j == 28), "ACL field %u length %u: got %u.\n", i, j, ret);
        }
        acl->AclSize = 7;
        ok(!RtlValidRelativeSecurityDescriptor(sd, 28, 0), "Accepted undersized ACL.\n");
        acl->AclSize = 9;
        ok(!RtlValidRelativeSecurityDescriptor(sd, 28, 0), "Accepted oversized ACL.\n");
        acl->AclSize = sizeof(*acl);
        acl->AceCount = 1;
        ok(!RtlValidRelativeSecurityDescriptor(sd, 28, 0), "Accepted ACL missing its ACE header.\n");
        acl->AceCount = 0;
        sd->Control &= ~present;
        *field = 0;
    }

    /* Place each advertised buffer immediately before an inaccessible page. */
    GetSystemInfo(&system_info);
    pages = VirtualAlloc(NULL, 2 * system_info.dwPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ok(!!pages, "Failed to allocate guard pages.\n");
    if (!pages) return;
    end = pages + system_info.dwPageSize;
    ret = VirtualProtect(end, system_info.dwPageSize, PAGE_NOACCESS, &old_protect);
    ok(ret, "Failed to protect guard page.\n");
    if (ret)
    {
        for (i = 0; i < sizeof(*sd); ++i)
        {
            copy = end - i;
            memcpy(copy, sd, i);
            ok(!RtlValidRelativeSecurityDescriptor(copy, i, 0), "Guarded short header %u accepted.\n", i);
        }
        sd->Owner = sizeof(*sd);
        sid->Revision = SID_REVISION;
        sid->SubAuthorityCount = 1;
        copy = end - 31;
        memcpy(copy, sd, 31);
        ok(!RtlValidRelativeSecurityDescriptor(copy, 31, 0), "Guarded short SID accepted.\n");
        sd->Owner = 0;
        sd->Control |= SE_DACL_PRESENT;
        sd->Dacl = sizeof(*sd);
        memset(acl, 0, sizeof(*acl));
        acl->AclRevision = ACL_REVISION;
        acl->AclSize = sizeof(*acl);
        acl->AceCount = 1;
        copy = end - 28;
        memcpy(copy, sd, 28);
        ok(!RtlValidRelativeSecurityDescriptor(copy, 28, 0), "Guarded missing ACE accepted.\n");
    }
    VirtualFree(pages, 0, MEM_RELEASE);
}

static void test_RtlValidAcl(void)
{
    static const BYTE sid_types[] = {0, 1, 2, 3, 9, 10, 13, 14, 17, 19, 20};
    static const BYTE object_types[] = {5, 6, 7, 8, 11, 12, 15, 16};
    union { ACL acl; BYTE bytes[128]; } buffer;
    ACL *acl = &buffer.acl;
    ACE_HEADER *ace = (ACE_HEADER *)(acl + 1);
    SID *sid = (SID *)((BYTE *)ace + 8);
    DWORD *flags = (DWORD *)((BYTE *)ace + 8);
    unsigned int i, j, sid_offset;

    memset(&buffer, 0, sizeof(buffer));
    acl->AclRevision = ACL_REVISION;
    for (i = 0; i <= sizeof(*acl); ++i)
    {
        acl->AclSize = i;
        ok(RtlValidAcl(acl) == (i == sizeof(*acl)), "ACL size %u validation failed.\n", i);
    }
    for (i = 0; i < 6; ++i)
    {
        acl->AclRevision = i;
        ok(RtlValidAcl(acl) == (i >= 2 && i <= 4), "ACL revision %u validation failed.\n", i);
    }
    acl->AclRevision = ACL_REVISION;
    acl->AceCount = 1;
    ace->AceType = 0xff;
    for (i = 0; i < sizeof(*ace); ++i)
    {
        acl->AclSize = sizeof(*acl) + i;
        ok(!RtlValidAcl(acl), "Accepted short ACE header %u.\n", i);
    }
    acl->AclSize = sizeof(*acl) + sizeof(*ace);
    for (i = 0; i <= 5; ++i)
    {
        ace->AceSize = i;
        ok(RtlValidAcl(acl) == (i == sizeof(*ace)), "ACE size %u validation failed.\n", i);
    }
    /* Unknown ACE types require a header, but their payload need not be DWORD-aligned. */
    ace->AceSize = 5;
    acl->AclSize = sizeof(*acl) + ace->AceSize;
    ok(RtlValidAcl(acl), "Rejected unknown ACE with an unaligned size.\n");
    ace->AceSize = sizeof(*ace);
    acl->AclSize = sizeof(*acl) + ace->AceSize;
    acl->AceCount = 2;
    ok(!RtlValidAcl(acl), "Accepted missing second ACE.\n");
    acl->AceCount = 1;
    for (i = 0; i < ARRAY_SIZE(sid_types); ++i)
    {
        ace->AceType = sid_types[i];
        ace->AceSize = 20;
        acl->AclSize = sizeof(*acl) + ace->AceSize;
        sid->Revision = SID_REVISION;
        sid->SubAuthorityCount = 1;
        ok(RtlValidAcl(acl), "Rejected valid SID ACE type %u.\n", ace->AceType);
        sid->Revision = 0;
        ok(!RtlValidAcl(acl), "Accepted bad SID revision type %u.\n", ace->AceType);
        sid->Revision = SID_REVISION;
        sid->SubAuthorityCount = 2;
        ok(!RtlValidAcl(acl), "Accepted truncated SID type %u.\n", ace->AceType);
        sid->SubAuthorityCount = 16;
        ok(!RtlValidAcl(acl), "Accepted too many subauthorities type %u.\n", ace->AceType);
        sid->SubAuthorityCount = 1;
        ace->AceSize = 19;
        ok(!RtlValidAcl(acl), "Accepted unaligned SID ACE type %u.\n", ace->AceType);
        ace->AceSize = 12;
        ok(!RtlValidAcl(acl), "Accepted missing SID type %u.\n", ace->AceType);
    }
    /* Compound ACEs contain separate server and client SIDs. */
    memset(ace, 0, 40);
    ace->AceType = ACCESS_ALLOWED_COMPOUND_ACE_TYPE;
    ace->AceSize = 36;
    acl->AclSize = sizeof(*acl) + ace->AceSize;
    acl->AclRevision = ACL_REVISION3;
    *(USHORT *)((BYTE *)ace + 8) = 1;
    sid = (SID *)((BYTE *)ace + 12);
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = 1;
    sid = (SID *)((BYTE *)ace + 24);
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = 1;
    ok(RtlValidAcl(acl), "Rejected compound ACE.\n");
    acl->AclRevision = ACL_REVISION;
    ok(!RtlValidAcl(acl), "Accepted compound ACE with old ACL revision.\n");
    acl->AclRevision = ACL_REVISION3;
    *(USHORT *)((BYTE *)ace + 8) = 0;
    ok(!RtlValidAcl(acl), "Accepted invalid compound type.\n");
    *(USHORT *)((BYTE *)ace + 8) = 1;
    sid->Revision = 0;
    ok(!RtlValidAcl(acl), "Accepted invalid compound client SID.\n");
    sid->Revision = SID_REVISION;
    sid->SubAuthorityCount = 2;
    ok(!RtlValidAcl(acl), "Accepted truncated compound client SID.\n");
    ace->AceSize = 32;
    sid->SubAuthorityCount = 1;
    ok(!RtlValidAcl(acl), "Accepted truncated compound ACE.\n");

    for (i = 0; i < ARRAY_SIZE(object_types); ++i)
    {
        ace->AceType = object_types[i];
        for (j = 0; j < 4; ++j)
        {
            *flags = j;
            sid_offset = 12 + (!!(j & 1) + !!(j & 2)) * sizeof(GUID);
            sid = (SID *)((BYTE *)ace + sid_offset);
            sid->Revision = SID_REVISION;
            sid->SubAuthorityCount = 1;
            ace->AceSize = sid_offset + sizeof(SID);
            acl->AclSize = sizeof(*acl) + ace->AceSize;
            acl->AclRevision = ACL_REVISION4;
            ok(RtlValidAcl(acl), "Rejected object type %u flags %u.\n", ace->AceType, j);
            acl->AclRevision = ACL_REVISION;
            ok(!RtlValidAcl(acl), "Accepted object type %u with old ACL revision.\n", ace->AceType);
            acl->AclRevision = ACL_REVISION4;
            sid->SubAuthorityCount = 2;
            ok(!RtlValidAcl(acl), "Accepted truncated object SID type %u flags %u.\n", ace->AceType, j);
        }
    }
}

static PSECURITY_DESCRIPTOR create_security_object_descriptor(BOOL owner_present, BOOL group_present)
{
    static const SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    SECURITY_DESCRIPTOR_RELATIVE *descriptor;
    BYTE *buffer;
    SID *owner, *group;
    ACL *dacl;
    NTSTATUS status;

    buffer = RtlAllocateHeap(GetProcessHeap(), HEAP_ZERO_MEMORY, 72);
    if (!buffer) return NULL;
    descriptor = (SECURITY_DESCRIPTOR_RELATIVE *)buffer;
    descriptor->Revision = SECURITY_DESCRIPTOR_REVISION;
    descriptor->Control = SE_SELF_RELATIVE | SE_DACL_PRESENT;
    descriptor->Dacl = 20;
    descriptor->Owner = owner_present ? 48 : 0;
    descriptor->Group = group_present ? 60 : 0;

    dacl = (ACL *)(buffer + descriptor->Dacl);
    status = RtlCreateAcl(dacl, 28, ACL_REVISION);
    ok(!status, "RtlCreateAcl returned %#lx.\n", status);

    owner = (SID *)(buffer + 48);
    status = RtlInitializeSid(owner, (SID_IDENTIFIER_AUTHORITY *)&authority, 1);
    ok(!status, "RtlInitializeSid returned %#lx.\n", status);
    *RtlSubAuthoritySid(owner, 0) = SECURITY_LOCAL_SYSTEM_RID;

    group = (SID *)(buffer + 60);
    status = RtlInitializeSid(group, (SID_IDENTIFIER_AUTHORITY *)&authority, 1);
    ok(!status, "RtlInitializeSid returned %#lx.\n", status);
    *RtlSubAuthoritySid(group, 0) = SECURITY_BUILTIN_DOMAIN_RID;

    status = RtlAddAccessAllowedAce(dacl, ACL_REVISION, 0x11, group);
    ok(!status, "RtlAddAccessAllowedAce returned %#lx.\n", status);
    return descriptor;
}

static void test_RtlCopySecurityDescriptor(void)
{
    PSECURITY_DESCRIPTOR source, copy = (void *)0xdeadbeef;
    NTSTATUS status;
    ULONG size;

    if (!pRtlCopySecurityDescriptor)
    {
        win_skip("RtlCopySecurityDescriptor is unavailable.\n");
        return;
    }

    source = create_security_object_descriptor(TRUE, TRUE);
    ok(!!source, "Failed to create source descriptor.\n");
    if (!source) return;

    size = RtlLengthSecurityDescriptor(source);
    ok(size == 72, "Got descriptor size %lu.\n", size);
    status = pRtlCopySecurityDescriptor(source, &copy);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    if (status == STATUS_SUCCESS)
    {
        ok(copy != source, "Copy aliases source descriptor.\n");
        ok(!memcmp(copy, source, size), "Copied descriptor differs from source.\n");
        ok(RtlValidSecurityDescriptor(copy), "Copied descriptor is invalid.\n");
        ((SECURITY_DESCRIPTOR *)source)->Revision = 2;
        ok(((SECURITY_DESCRIPTOR *)copy)->Revision == SECURITY_DESCRIPTOR_REVISION,
           "Copy changed with source descriptor.\n");
        status = RtlDeleteSecurityObject(&copy);
        ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    }

    RtlFreeHeap(GetProcessHeap(), 0, source);
}

static void test_RtlSetSecurityObject(void)
{
    static const SID_IDENTIFIER_AUTHORITY authority = SECURITY_NT_AUTHORITY;
    const GENERIC_MAPPING mapping = {0x123, 0x456, 0x789, 0xabc};
    SECURITY_DESCRIPTOR modification;
    SECURITY_DESCRIPTOR_RELATIVE *relative;
    PSECURITY_DESCRIPTOR descriptor, original;
    BYTE replacement_acl_buffer[28];
    BOOLEAN present, defaulted;
    ACL *replacement_acl, *result_acl;
    ACCESS_ALLOWED_ACE *ace;
    SID replacement_sid;
    NTSTATUS status;

    replacement_acl = (ACL *)replacement_acl_buffer;
    status = RtlCreateAcl(replacement_acl, sizeof(replacement_acl_buffer), ACL_REVISION);
    ok(!status, "RtlCreateAcl returned %#lx.\n", status);
    status = RtlInitializeSid(&replacement_sid, (SID_IDENTIFIER_AUTHORITY *)&authority, 1);
    ok(!status, "RtlInitializeSid returned %#lx.\n", status);
    *RtlSubAuthoritySid(&replacement_sid, 0) = SECURITY_BUILTIN_DOMAIN_RID;
    status = RtlAddAccessAllowedAce(replacement_acl, ACL_REVISION, GENERIC_READ, &replacement_sid);
    ok(!status, "RtlAddAccessAllowedAce returned %#lx.\n", status);

    status = RtlCreateSecurityDescriptor(&modification, SECURITY_DESCRIPTOR_REVISION);
    ok(!status, "RtlCreateSecurityDescriptor returned %#lx.\n", status);
    status = RtlSetDaclSecurityDescriptor(&modification, TRUE, replacement_acl, FALSE);
    ok(!status, "RtlSetDaclSecurityDescriptor returned %#lx.\n", status);
    modification.Control |= SE_DACL_PROTECTED | SE_DACL_AUTO_INHERITED;

    descriptor = create_security_object_descriptor(TRUE, TRUE);
    original = descriptor;
    status = RtlSetSecurityObject(DACL_SECURITY_INFORMATION, &modification, &descriptor,
                                  (GENERIC_MAPPING *)&mapping, NULL);
    ok(!status, "RtlSetSecurityObject returned %#lx.\n", status);
    ok(descriptor != original, "Expected the descriptor allocation to be replaced.\n");
    relative = descriptor;
    ok(relative->Control == (SE_SELF_RELATIVE | SE_DACL_PRESENT | SE_DACL_PROTECTED),
       "Unexpected control %#x.\n", relative->Control);
    ok(relative->Dacl == 20, "Unexpected DACL offset %lu.\n", relative->Dacl);
    ok(relative->Owner == 48, "Unexpected owner offset %lu.\n", relative->Owner);
    ok(relative->Group == 60, "Unexpected group offset %lu.\n", relative->Group);
    status = RtlGetDaclSecurityDescriptor(descriptor, &present, &result_acl, &defaulted);
    ok(!status && present && !defaulted, "Unexpected DACL result %#lx, %u, %u.\n",
       status, present, defaulted);
    ace = (ACCESS_ALLOWED_ACE *)(result_acl + 1);
    ok(ace->Mask == (mapping.GenericRead & mapping.GenericAll), "Unexpected mapped mask %#lx.\n", ace->Mask);
    status = RtlDeleteSecurityObject(&descriptor);
    ok(!status, "RtlDeleteSecurityObject returned %#lx.\n", status);

    descriptor = create_security_object_descriptor(FALSE, TRUE);
    original = descriptor;
    status = RtlSetSecurityObject(DACL_SECURITY_INFORMATION, &modification, &descriptor,
                                  (GENERIC_MAPPING *)&mapping, NULL);
    ok(status == STATUS_INVALID_OWNER, "Expected STATUS_INVALID_OWNER, got %#lx.\n", status);
    ok(descriptor == original, "Descriptor changed on failure.\n");
    RtlFreeHeap(GetProcessHeap(), 0, descriptor);

    descriptor = create_security_object_descriptor(TRUE, FALSE);
    original = descriptor;
    status = RtlSetSecurityObject(DACL_SECURITY_INFORMATION, &modification, &descriptor,
                                  (GENERIC_MAPPING *)&mapping, NULL);
    ok(status == STATUS_INVALID_PRIMARY_GROUP, "Expected STATUS_INVALID_PRIMARY_GROUP, got %#lx.\n", status);
    ok(descriptor == original, "Descriptor changed on failure.\n");
    RtlFreeHeap(GetProcessHeap(), 0, descriptor);
}

static void test_RtlCreateAndSetSD(void)
{
    struct sid2
    {
        SID sid;
        ULONG second_subauthority;
    } group_sid = { { SID_REVISION, 2, { SECURITY_NT_AUTHORITY },
                      { SECURITY_BUILTIN_DOMAIN_RID } }, DOMAIN_ALIAS_RID_ADMINS };
    SID owner_sid = { SID_REVISION, 1, { SECURITY_NT_AUTHORITY }, { SECURITY_LOCAL_SYSTEM_RID } };
    PSID owner = &owner_sid, group = &group_sid.sid;
    RTL_ACE_DATA ace_data[3];
    SECURITY_DESCRIPTOR *sd;
    ACE_HEADER *header;
    ACCESS_MASK mask;
    NTSTATUS status;
    void *ace;

    if (!pRtlCreateAndSetSD)
    {
        win_skip("RtlCreateAndSetSD is unavailable.\n");
        return;
    }

    ok(sizeof(RTL_ACE_DATA) == (is_win64 ? 16 : 12), "Got structure size %Iu.\n",
       sizeof(RTL_ACE_DATA));
    ok(FIELD_OFFSET(RTL_ACE_DATA, Mask) == 4, "Got mask offset %lu.\n",
       FIELD_OFFSET(RTL_ACE_DATA, Mask));
    ok(FIELD_OFFSET(RTL_ACE_DATA, Sid) == 8, "Got SID offset %lu.\n",
       FIELD_OFFSET(RTL_ACE_DATA, Sid));

    memset(ace_data, 0, sizeof(ace_data));
    ace_data[0].AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace_data[0].InheritFlags = OBJECT_INHERIT_ACE;
    ace_data[0].AceFlags = INHERITED_ACE;
    ace_data[0].Mask = GENERIC_READ;
    ace_data[0].Sid = &owner;
    ace_data[1].AceType = ACCESS_DENIED_ACE_TYPE;
    ace_data[1].InheritFlags = CONTAINER_INHERIT_ACE;
    ace_data[1].Mask = GENERIC_WRITE;
    ace_data[1].Sid = &group;
    ace_data[2].AceType = SYSTEM_AUDIT_ACE_TYPE;
    ace_data[2].AceFlags = SUCCESSFUL_ACCESS_ACE_FLAG;
    ace_data[2].Mask = GENERIC_EXECUTE;
    ace_data[2].Sid = &owner;

    sd = (void *)0xdeadbeef;
    status = pRtlCreateAndSetSD(ace_data, ARRAY_SIZE(ace_data), owner, group,
                                (PSECURITY_DESCRIPTOR *)&sd);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    if (status == STATUS_SUCCESS)
    {
        ok(sd->Revision == SECURITY_DESCRIPTOR_REVISION, "Got revision %u.\n", sd->Revision);
        ok(sd->Control == (SE_DACL_PRESENT | SE_SACL_PRESENT), "Got control %#x.\n", sd->Control);
        ok(sd->Owner == owner, "Got owner %p.\n", sd->Owner);
        ok(sd->Group == group, "Got group %p.\n", sd->Group);
        ok(sd->Dacl == (ACL *)(sd + 1), "Got DACL %p, expected %p.\n", sd->Dacl, sd + 1);
        ok(sd->Sacl == (ACL *)((BYTE *)sd->Dacl + sd->Dacl->AclSize),
           "Got SACL %p, expected %p.\n", sd->Sacl, (BYTE *)sd->Dacl + sd->Dacl->AclSize);
        ok(sd->Dacl->AclRevision == ACL_REVISION, "Got DACL revision %u.\n", sd->Dacl->AclRevision);
        ok(sd->Dacl->AceCount == 2, "Got DACL ACE count %u.\n", sd->Dacl->AceCount);
        ok(sd->Dacl->AclSize == sizeof(ACL) + RtlLengthSid(owner) + 12 + RtlLengthSid(group) + 12,
           "Got DACL size %u.\n", sd->Dacl->AclSize);

        status = RtlGetAce(sd->Dacl, 0, &ace);
        ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
        header = ace;
        memcpy(&mask, (BYTE *)ace + sizeof(*header), sizeof(mask));
        ok(header->AceType == ACCESS_ALLOWED_ACE_TYPE, "Got ACE type %u.\n", header->AceType);
        ok(header->AceFlags == (OBJECT_INHERIT_ACE | INHERITED_ACE), "Got ACE flags %#x.\n",
           header->AceFlags);
        ok(header->AceSize == RtlLengthSid(owner) + 12, "Got ACE size %u.\n", header->AceSize);
        ok(mask == GENERIC_READ, "Got access mask %#lx.\n", mask);
        ok(RtlEqualSid((BYTE *)ace + sizeof(*header) + sizeof(mask), owner), "Got wrong SID.\n");

        status = RtlGetAce(sd->Dacl, 1, &ace);
        ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
        header = ace;
        memcpy(&mask, (BYTE *)ace + sizeof(*header), sizeof(mask));
        ok(header->AceType == ACCESS_DENIED_ACE_TYPE, "Got ACE type %u.\n", header->AceType);
        ok(header->AceFlags == CONTAINER_INHERIT_ACE, "Got ACE flags %#x.\n", header->AceFlags);
        ok(header->AceSize == RtlLengthSid(group) + 12, "Got ACE size %u.\n", header->AceSize);
        ok(mask == GENERIC_WRITE, "Got access mask %#lx.\n", mask);
        ok(RtlEqualSid((BYTE *)ace + sizeof(*header) + sizeof(mask), group), "Got wrong SID.\n");

        ok(sd->Sacl->AclRevision == ACL_REVISION, "Got SACL revision %u.\n", sd->Sacl->AclRevision);
        ok(sd->Sacl->AceCount == 1, "Got SACL ACE count %u.\n", sd->Sacl->AceCount);
        ok(sd->Sacl->AclSize == sizeof(ACL) + RtlLengthSid(owner) + 12,
           "Got SACL size %u.\n", sd->Sacl->AclSize);
        status = RtlGetAce(sd->Sacl, 0, &ace);
        ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
        header = ace;
        memcpy(&mask, (BYTE *)ace + sizeof(*header), sizeof(mask));
        ok(header->AceType == SYSTEM_AUDIT_ACE_TYPE, "Got ACE type %u.\n", header->AceType);
        ok(header->AceFlags == SUCCESSFUL_ACCESS_ACE_FLAG, "Got ACE flags %#x.\n", header->AceFlags);
        ok(header->AceSize == RtlLengthSid(owner) + 12, "Got ACE size %u.\n", header->AceSize);
        ok(mask == GENERIC_EXECUTE, "Got access mask %#lx.\n", mask);
        ok(RtlEqualSid((BYTE *)ace + sizeof(*header) + sizeof(mask), owner), "Got wrong SID.\n");

        status = RtlDeleteSecurityObject((PSECURITY_DESCRIPTOR *)&sd);
        ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    }

    sd = (void *)0xdeadbeef;
    status = pRtlCreateAndSetSD(NULL, 0, owner, group, (PSECURITY_DESCRIPTOR *)&sd);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    if (status == STATUS_SUCCESS)
    {
        ok(sd->Control == SE_DACL_PRESENT, "Got control %#x.\n", sd->Control);
        ok(sd->Owner == owner, "Got owner %p.\n", sd->Owner);
        ok(sd->Group == group, "Got group %p.\n", sd->Group);
        ok(!sd->Dacl, "Got DACL %p.\n", sd->Dacl);
        ok(!sd->Sacl, "Got SACL %p.\n", sd->Sacl);
        status = RtlDeleteSecurityObject((PSECURITY_DESCRIPTOR *)&sd);
        ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    }

    ace_data[0].AceType = 3;
    sd = (void *)0xdeadbeef;
    status = pRtlCreateAndSetSD(ace_data, 1, owner, group, (PSECURITY_DESCRIPTOR *)&sd);
    ok(status == STATUS_INVALID_PARAMETER, "Got status %#lx.\n", status);
    ok(sd == (void *)0xdeadbeef, "Output changed to %p.\n", sd);
}

static void test_RtlCreateUserSecurityObject(void)
{
    GENERIC_MAPPING mapping = { 0x0001, 0x0002, 0x0004, 0x000f };
    TOKEN_PRIMARY_GROUP *token_group = NULL;
    TOKEN_OWNER *token_owner = NULL;
    PSECURITY_DESCRIPTOR sd = NULL;
    RTL_ACE_DATA ace_data;
    BOOLEAN present, defaulted;
    SECURITY_DESCRIPTOR_CONTROL control;
    ACCESS_ALLOWED_ACE *ace;
    PSID owner, group;
    HANDLE token;
    ACL *dacl;
    DWORD size;
    ULONG revision;
    NTSTATUS status;

    if (!pRtlCreateUserSecurityObject)
    {
        win_skip("RtlCreateUserSecurityObject is unavailable.\n");
        return;
    }

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
    {
        win_skip("Failed to open the process token, error %lu.\n", GetLastError());
        return;
    }

    size = 0;
    GetTokenInformation(token, TokenOwner, NULL, 0, &size);
    token_owner = HeapAlloc(GetProcessHeap(), 0, size);
    if (!token_owner || !GetTokenInformation(token, TokenOwner, token_owner, size, &size))
    {
        win_skip("Failed to query the token owner, error %lu.\n", GetLastError());
        goto done;
    }

    size = 0;
    GetTokenInformation(token, TokenPrimaryGroup, NULL, 0, &size);
    token_group = HeapAlloc(GetProcessHeap(), 0, size);
    if (!token_group || !GetTokenInformation(token, TokenPrimaryGroup, token_group, size, &size))
    {
        win_skip("Failed to query the token primary group, error %lu.\n", GetLastError());
        goto done;
    }

    memset(&ace_data, 0, sizeof(ace_data));
    owner = token_owner->Owner;
    group = token_group->PrimaryGroup;
    ace_data.AceType = ACCESS_ALLOWED_ACE_TYPE;
    ace_data.Mask = GENERIC_READ;
    ace_data.Sid = &owner;

    status = pRtlCreateUserSecurityObject(&ace_data, 1, owner, group, FALSE, &mapping, &sd);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    if (status) goto done;

    status = RtlGetControlSecurityDescriptor(sd, &control, &revision);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ok(control & SE_SELF_RELATIVE, "Descriptor is not self-relative, control %#x.\n", control);

    status = RtlGetOwnerSecurityDescriptor(sd, &owner, &defaulted);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ok(RtlEqualSid(owner, token_owner->Owner), "Got wrong owner SID.\n");
    status = RtlGetGroupSecurityDescriptor(sd, &group, &defaulted);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ok(RtlEqualSid(group, token_group->PrimaryGroup), "Got wrong group SID.\n");

    status = RtlGetDaclSecurityDescriptor(sd, &present, &dacl, &defaulted);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
    ok(present && dacl && dacl->AceCount == 1, "Got DACL %p, present %u, ACE count %u.\n",
       dacl, present, dacl ? dacl->AceCount : 0);
    if (present && dacl && dacl->AceCount == 1)
    {
        status = RtlGetAce(dacl, 0, (void **)&ace);
        ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);
        ok(ace->Header.AceType == ACCESS_ALLOWED_ACE_TYPE, "Got ACE type %u.\n",
           ace->Header.AceType);
        ok(ace->Mask == mapping.GenericRead, "Got access mask %#lx.\n", ace->Mask);
        ok(RtlEqualSid(&ace->SidStart, token_owner->Owner), "Got wrong ACE SID.\n");
    }

    status = RtlDeleteSecurityObject(&sd);
    ok(status == STATUS_SUCCESS, "Got status %#lx.\n", status);

done:
    HeapFree(GetProcessHeap(), 0, token_group);
    HeapFree(GetProcessHeap(), 0, token_owner);
    CloseHandle(token);
}

static void test_RtlFindExportedRoutineByName(void)
{
    void *proc;

    if (!pRtlFindExportedRoutineByName)
    {
        win_skip( "RtlFindExportedRoutineByName is not present\n" );
        return;
    }
    proc = pRtlFindExportedRoutineByName( GetModuleHandleW( L"kernelbase" ), "CtrlRoutine" );
    ok( proc != NULL, "Expected non NULL address\n" );
    proc = pRtlFindExportedRoutineByName( GetModuleHandleW( L"kernel32" ), "CtrlRoutine" );
    ok( proc == NULL, "Shouldn't find forwarded function\n" );
}

static void test_RtlGetDeviceFamilyInfoEnum(void)
{
    ULONGLONG version;
    DWORD family, form;

    if (!pRtlGetDeviceFamilyInfoEnum)
    {
        win_skip( "RtlGetDeviceFamilyInfoEnum is not present\n" );
        return;
    }

    version = 0x1234567;
    family = 1234567;
    form = 1234567;
    pRtlGetDeviceFamilyInfoEnum(&version, &family, &form);
    ok( version != 0x1234567, "got unexpected unchanged value 0x1234567\n" );
    ok( family <= DEVICEFAMILYINFOENUM_MAX, "got unexpected %lu\n", family );
    ok( form <= DEVICEFAMILYDEVICEFORM_MAX, "got unexpected %lu\n", form );
    trace( "UAP version is %#I64x, device family is %lu, form factor is %lu\n", version, family, form );
}

struct test_rb_tree_entry
{
    int value;
    struct rb_entry wine_rb_entry;
    RTL_BALANCED_NODE rtl_entry;
};

static int test_rb_tree_entry_compare( const void *key, const struct wine_rb_entry *entry )
{
    const struct test_rb_tree_entry *t = WINE_RB_ENTRY_VALUE(entry, struct test_rb_tree_entry, wine_rb_entry);
    const int *value = key;

    return *value - t->value;
}

static int test_rtl_rb_tree_entry_compare( const void *key, const RTL_BALANCED_NODE *entry )
{
    const struct test_rb_tree_entry *t = CONTAINING_RECORD(entry, struct test_rb_tree_entry, rtl_entry);
    const int *value = key;

    return *value - t->value;
}

static int rtl_rb_tree_put( RTL_RB_TREE *tree, const void *key, RTL_BALANCED_NODE *entry,
                            int (*compare_func)( const void *key, const RTL_BALANCED_NODE *entry ))
{
    RTL_BALANCED_NODE *parent = tree->root;
    BOOLEAN right = 0;
    int c;

    while (parent)
    {
        if (!(c = compare_func( key, parent ))) return -1;
        right = c > 0;
        if (!parent->Children[right]) break;
        parent = parent->Children[right];
    }
    pRtlRbInsertNodeEx( tree, parent, right, entry );
    return 0;
}

static struct test_rb_tree_entry *test_rb_tree_entry_from_wine_rb( struct rb_entry *entry )
{
    if (!entry) return NULL;
    return CONTAINING_RECORD(entry, struct test_rb_tree_entry, wine_rb_entry);
}

static struct test_rb_tree_entry *test_rb_tree_entry_from_rtl_rb( RTL_BALANCED_NODE *entry )
{
    if (!entry) return NULL;
    return CONTAINING_RECORD(entry, struct test_rb_tree_entry, rtl_entry);
}

static struct test_rb_tree_entry *test_rb_tree_entry_rtl_parent( struct test_rb_tree_entry *node )
{
    return test_rb_tree_entry_from_rtl_rb( (void *)(node->rtl_entry.ParentValue
                                           & ~(ULONG_PTR)RTL_BALANCED_NODE_RESERVED_PARENT_MASK) );
}

static void test_rb_tree(void)
{
    static int test_values[] = { 44, 51, 6, 66, 69, 20, 87, 80, 72, 86, 90, 16, 54, 61, 62, 14, 27, 39, 42, 41 };
    static const unsigned int count = ARRAY_SIZE(test_values);

    struct test_rb_tree_entry *nodes, *parent, *parent2;
    RTL_BALANCED_NODE *prev_min_entry = NULL;
    int ret, is_red, min_val;
    struct rb_tree wine_tree;
    RTL_RB_TREE rtl_tree;
    unsigned int i;

    if (!pRtlRbInsertNodeEx)
    {
        win_skip( "RtlRbInsertNodeEx is not present.\n" );
        return;
    }

    memset( &rtl_tree, 0, sizeof(rtl_tree) );
    nodes = malloc( count * sizeof(*nodes) );
    memset( nodes, 0xcc, count * sizeof(*nodes) );

    min_val = test_values[0];
    rb_init( &wine_tree, test_rb_tree_entry_compare );
    for (i = 0; i < count; ++i)
    {
        winetest_push_context( "i %u", i );
        nodes[i].value = test_values[i];
        ret = rb_put( &wine_tree, &nodes[i].value, &nodes[i].wine_rb_entry );
        ok( !ret, "got %d.\n", ret );
        parent = test_rb_tree_entry_from_wine_rb( nodes[i].wine_rb_entry.parent );
        ret = rtl_rb_tree_put( &rtl_tree, &nodes[i].value, &nodes[i].rtl_entry, test_rtl_rb_tree_entry_compare );
        ok( !ret, "got %d.\n", ret );
        parent2 = test_rb_tree_entry_rtl_parent( &nodes[i] );
        ok( parent == parent2, "got %p, %p.\n", parent, parent2 );
        is_red = nodes[i].rtl_entry.ParentValue & RTL_BALANCED_NODE_RESERVED_PARENT_MASK;
        ok( is_red == rb_is_red( &nodes[i].wine_rb_entry ), "got %d, expected %d.\n", is_red,
            rb_is_red( &nodes[i].wine_rb_entry ));

        parent = test_rb_tree_entry_from_wine_rb( wine_tree.root );
        parent2 = test_rb_tree_entry_from_rtl_rb( rtl_tree.root );
        ok( parent == parent2, "got %p, %p.\n", parent, parent2 );
        if (nodes[i].value <= min_val)
        {
            min_val = nodes[i].value;
            prev_min_entry = &nodes[i].rtl_entry;
        }
        ok( rtl_tree.min == prev_min_entry, "unexpected min tree entry.\n" );
        winetest_pop_context();
    }

    for (i = 0; i < count; ++i)
    {
        struct test_rb_tree_entry *node;

        winetest_push_context( "i %u", i );
        rb_remove( &wine_tree, &nodes[i].wine_rb_entry );
        pRtlRbRemoveNode( &rtl_tree, &nodes[i].rtl_entry );

        parent = test_rb_tree_entry_from_wine_rb( wine_tree.root );
        parent2 = test_rb_tree_entry_from_rtl_rb( rtl_tree.root );
        ok( parent == parent2, "got %p, %p.\n", parent, parent2 );

        parent = test_rb_tree_entry_from_wine_rb( rb_head( wine_tree.root ));
        parent2 = test_rb_tree_entry_from_rtl_rb( rtl_tree.min );
        ok( parent == parent2, "got %p, %p.\n", parent, parent2 );

        RB_FOR_EACH_ENTRY(node, &wine_tree, struct test_rb_tree_entry, wine_rb_entry)
        {
            is_red = node->rtl_entry.ParentValue & RTL_BALANCED_NODE_RESERVED_PARENT_MASK;
            ok( is_red == rb_is_red( &node->wine_rb_entry ), "got %d, expected %d.\n", is_red, rb_is_red( &node->wine_rb_entry ));
            parent = test_rb_tree_entry_from_wine_rb( node->wine_rb_entry.parent );
            parent2 = test_rb_tree_entry_rtl_parent( node );
            ok( parent == parent2, "got %p, %p.\n", parent, parent2 );
        }
        winetest_pop_context();
    }
    ok( !rtl_tree.root, "got %p.\n", rtl_tree.root );
    ok( !rtl_tree.min, "got %p.\n", rtl_tree.min );
    free(nodes);
}

static void test_RtlConvertDeviceFamilyInfoToString(void)
{
    DWORD device_family_size, device_form_size, ret;
    WCHAR device_family[16], device_form[16];

    if (!pRtlConvertDeviceFamilyInfoToString)
    {
        win_skip("RtlConvertDeviceFamilyInfoToString is unavailable.\n" );
        return;
    }

    if (0) /* Crash on Windows */
    {
    ret = pRtlConvertDeviceFamilyInfoToString(NULL, NULL, NULL, NULL);
    ok(ret == STATUS_INVALID_PARAMETER, "Got unexpected status %#lx.\n", ret);

    device_family_size = 0;
    ret = pRtlConvertDeviceFamilyInfoToString(&device_family_size, NULL, NULL, NULL);
    ok(ret == STATUS_BUFFER_TOO_SMALL, "Got unexpected status %#lx.\n", ret);
    ok(device_family_size == (wcslen(L"Windows.Desktop") + 1) * sizeof(WCHAR),
       "Got unexpected %#lx.\n", device_family_size);

    device_form_size = 0;
    ret = pRtlConvertDeviceFamilyInfoToString(NULL, &device_form_size, NULL, NULL);
    ok(ret == STATUS_BUFFER_TOO_SMALL, "Got unexpected status %#lx.\n", ret);
    ok(device_form_size == (wcslen(L"Unknown") + 1) * sizeof(WCHAR), "Got unexpected %#lx.\n",
       device_form_size);

    ret = pRtlConvertDeviceFamilyInfoToString(&device_family_size, NULL, device_family, NULL);
    ok(ret == STATUS_SUCCESS, "Got unexpected status %#lx.\n", ret);
    ok(device_family_size == (wcslen(L"Windows.Desktop") + 1) * sizeof(WCHAR),
       "Got unexpected %#lx.\n", device_family_size);
    ok(!wcscmp(device_family, L"Windows.Desktop"), "Got unexpected %s.\n", wine_dbgstr_w(device_family));

    ret = pRtlConvertDeviceFamilyInfoToString(NULL, &device_form_size, NULL, device_form);
    ok(ret == STATUS_SUCCESS, "Got unexpected status %#lx.\n", ret);
    ok(device_form_size == (wcslen(L"Unknown") + 1) * sizeof(WCHAR), "Got unexpected %#lx.\n",
       device_form_size);
    ok(!wcscmp(device_form, L"Unknown"), "Got unexpected %s.\n", wine_dbgstr_w(device_form));

    ret = pRtlConvertDeviceFamilyInfoToString(&device_family_size, &device_form_size, NULL, NULL);
    ok(ret == STATUS_INVALID_PARAMETER, "Got unexpected status %#lx.\n", ret);
    }

    device_family_size = wcslen(L"Windows.Desktop") * sizeof(WCHAR);
    device_form_size = wcslen(L"Unknown") * sizeof(WCHAR);
    ret = pRtlConvertDeviceFamilyInfoToString(&device_family_size, &device_form_size, NULL, NULL);
    ok(ret == STATUS_BUFFER_TOO_SMALL, "Got unexpected status %#lx.\n", ret);
    ok(device_family_size == (wcslen(L"Windows.Desktop") + 1) * sizeof(WCHAR),
       "Got unexpected %#lx.\n", device_family_size);
    ok(device_form_size == (wcslen(L"Unknown") + 1) * sizeof(WCHAR), "Got unexpected %#lx.\n",
       device_form_size);

    ret = pRtlConvertDeviceFamilyInfoToString(&device_family_size, &device_form_size, device_family, device_form);
    ok(ret == STATUS_SUCCESS, "Got unexpected status %#lx.\n", ret);
    ok(!wcscmp(device_family, L"Windows.Desktop"), "Got unexpected %s.\n", wine_dbgstr_w(device_family));
    ok(!wcscmp(device_form, L"Unknown"), "Got unexpected %s.\n", wine_dbgstr_w(device_form));
}

static void test_user_procs(void)
{
    UINT64 ptrs[32], dummy[32] = { 0 };
    NTSTATUS status;
    const UINT64 *ptr_A, *ptr_W, *ptr_workers;
    ULONG size_A, size_W, size_workers;

    if (!pRtlRetrieveNtUserPfn || !pRtlInitializeNtUserPfn)
    {
        win_skip( "user procs not supported\n" );
        return;
    }

    status = pRtlRetrieveNtUserPfn( &ptr_A, &ptr_W, &ptr_workers );
    ok( !status || broken(!is_win64 && status == STATUS_INVALID_PARAMETER), /* <= win8 32-bit */
        "RtlRetrieveNtUserPfn failed %lx\n", status );
    if (status) return;

    /* assume that the tables are consecutive */
    size_A = (ptr_W - ptr_A) * sizeof(UINT64);
    size_W = (ptr_workers - ptr_W) * sizeof(UINT64);
    ok( size_A > 0x80 && size_A < 0x100, "unexpected size for %p %p %p\n", ptr_A, ptr_W, ptr_workers );
    ok( size_W == size_A, "unexpected size for %p %p %p\n", ptr_A, ptr_W, ptr_workers );
    memcpy( ptrs, ptr_A, size_A );

    status = pRtlInitializeNtUserPfn( dummy, size_A, dummy + 1, size_W, dummy + 2, 0 );
    ok( status == STATUS_INVALID_PARAMETER, "RtlInitializeNtUserPfn failed %lx\n", status );

    if (!pRtlResetNtUserPfn)
    {
        win_skip( "RtlResetNtUserPfn not supported\n" );
        return;
    }

    status = pRtlResetNtUserPfn();
    ok( !status, "RtlResetNtUserPfn failed %lx\n", status );
    ok( !memcmp( ptrs, ptr_A, size_A ), "pointers changed by reset\n" );

    /* can't do anything after reset except set them again */
    status = pRtlResetNtUserPfn();
    ok( status == STATUS_INVALID_PARAMETER, "RtlResetNtUserPfn failed %lx\n", status );
    status = pRtlRetrieveNtUserPfn( &ptr_A, &ptr_W, &ptr_workers );
    ok( status == STATUS_INVALID_PARAMETER, "RtlRetrieveNtUserPfn failed %lx\n", status );

    for (size_workers = 0x100; size_workers > 0; size_workers--)
    {
        status = pRtlInitializeNtUserPfn( dummy, size_A, dummy + 1, size_W, dummy + 2, size_workers );
        if (!status) break;
        ok( status == STATUS_INVALID_PARAMETER, "RtlInitializeNtUserPfn failed %lx\n", status );
    }
    trace( "got sizes %lx %lx %lx\n", size_A, size_W, size_workers );
    if (!size_workers) return;  /* something went wrong */
    ok( !memcmp( ptrs, ptr_A, size_A ), "pointers changed by init\n" );

    /* can't set twice without a reset */
    status = pRtlInitializeNtUserPfn( dummy, size_A, dummy + 1, size_W, dummy + 2, size_workers );
    ok( status == STATUS_INVALID_PARAMETER, "RtlInitializeNtUserPfn failed %lx\n", status );
    status = pRtlResetNtUserPfn();
    ok( !status, "RtlResetNtUserPfn failed %lx\n", status );
    status = pRtlInitializeNtUserPfn( dummy, size_A, dummy + 1, size_W, dummy + 2, size_workers );
    ok( !status, "RtlInitializeNtUserPfn failed %lx\n", status );
    ok( !memcmp( ptrs, ptr_A, size_A ), "pointers changed by init\n" );
}

struct splay_index
{
    int parent_index;
    int left_index;
    int right_index;
};

static void init_splay_indices(RTL_SPLAY_LINKS *links, unsigned int links_count,
                               const struct splay_index *indices, unsigned int index_count)
{
    const struct splay_index *index;
    unsigned int i;

    for (i = 0; i < links_count; i++)
        RtlInitializeSplayLinks(&links[i]);
    for (i = 0; i < index_count; i++)
    {
        index = &indices[i];
        if (index->left_index != -1)
            RtlInsertAsLeftChild(&links[index->parent_index], &links[index->left_index]);
        if (index->right_index != -1)
            RtlInsertAsRightChild(&links[index->parent_index], &links[index->right_index]);
    }
}

#define expect_splay_indices(a, b, c, d) _expect_splay_indices(__LINE__, a, b, c, d)
static void _expect_splay_indices(int line, RTL_SPLAY_LINKS *links, RTL_SPLAY_LINKS *root,
                                  const struct splay_index *indices, unsigned int index_count)
{
    const struct splay_index *index;
    unsigned int i;

    ok_(__FILE__, line)(RtlIsRoot(root), "Got unexpected root node %d.\n", root ? (int)(root - links) : -1);
    ok_(__FILE__, line)(root == &links[indices[0].parent_index], "Expected root %d, got %d.\n",
                        indices[0].parent_index, root ? (int)(root - links) : -1);

    for (i = 0; i < index_count; i++)
    {
        winetest_push_context("%d", i);

        index = &indices[i];
        if (index->left_index != -1)
        {
            ok_(__FILE__, line)(links[index->parent_index].LeftChild == &links[index->left_index],
                                "Node %d got unexpected left child %d.\n", index->parent_index,
                                links[index->parent_index].LeftChild ?
                                (int)(links[index->parent_index].LeftChild - links) : -1);
            ok_(__FILE__, line)(links[index->left_index].Parent == &links[index->parent_index],
                                "Node %d got unexpected parent %d.\n", index->left_index,
                                (int)(links[index->left_index].Parent - links));
        }
        else
        {
            ok_(__FILE__, line)(!links[index->parent_index].LeftChild,
                                "Node %d shouldn't have left child %d.\n",
                                index->parent_index, (int)(links[index->parent_index].LeftChild - links));
        }

        if (index->right_index != -1)
        {
            ok_(__FILE__, line)(links[index->parent_index].RightChild == &links[index->right_index],
                                "Node %d got unexpected right child %d.\n", index->parent_index,
                                links[index->parent_index].RightChild ?
                                (int)(links[index->parent_index].RightChild - links) : -1);
            ok_(__FILE__, line)(links[index->right_index].Parent == &links[index->parent_index],
                                "Node %d got unexpected parent %d.\n", index->right_index,
                                (int)(links[index->right_index].Parent - links));
        }
        else
        {
            ok_(__FILE__, line)(!links[index->parent_index].RightChild,
                                "Node %d shouldn't have right child %d.\n",
                                index->parent_index, (int)(links[index->parent_index].RightChild - links));
        }

        winetest_pop_context();
    }
}

static void test_RtlSubtreePredecessor(void)
{
    /*       3
     *     /   \
     *    1     5
     *   / \   / \
     *  0   2 4   6
     */
    static const struct splay_index splay_indices[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
    };
    static const int expected_predecessors[] = {-1, 0, -1, 2, -1, 4, -1};
    RTL_SPLAY_LINKS links[7], *predecessor;
    unsigned int i;

    if (!pRtlSubtreePredecessor)
    {
        win_skip("RtlSubtreePredecessor is unavailable.\n");
        return;
    }

    init_splay_indices(links, ARRAY_SIZE(links), splay_indices, ARRAY_SIZE(splay_indices));
    for (i = 0; i < ARRAY_SIZE(expected_predecessors); i++)
    {
        winetest_push_context("%d", i);

        predecessor = pRtlSubtreePredecessor(&links[i]);
        if (expected_predecessors[i] == -1)
            ok(!predecessor, "Expected NULL, got unexpected %d.\n", (int)(predecessor - links));
        else
            ok(predecessor == &links[expected_predecessors[i]], "Expected %d, got unexpected %d.\n",
               expected_predecessors[i], (int)(predecessor ? predecessor - links : -1));

        winetest_pop_context();
    }
}

static void test_RtlSubtreeSuccessor(void)
{
    /*       3
     *     /   \
     *    1     5
     *   / \   / \
     *  0   2 4   6
     */
    static const struct splay_index splay_indices[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
    };
    static const int expected_successors[] = {-1, 2, -1, 4, -1, 6, -1};
    RTL_SPLAY_LINKS links[7], *successor;
    unsigned int i;

    if (!pRtlSubtreeSuccessor)
    {
        win_skip("RtlSubtreeSuccessor is unavailable.\n");
        return;
    }

    init_splay_indices(links, ARRAY_SIZE(links), splay_indices, ARRAY_SIZE(splay_indices));
    for (i = 0; i < ARRAY_SIZE(expected_successors); i++)
    {
        winetest_push_context("%d", i);

        successor = pRtlSubtreeSuccessor(&links[i]);
        if (expected_successors[i] == -1)
            ok(!successor, "Expected NULL, got unexpected %d.\n", (int)(successor - links));
        else
            ok(successor == &links[expected_successors[i]], "Expected %d, got unexpected %d.\n",
               expected_successors[i], (int)(successor ? successor - links : -1));

        winetest_pop_context();
    }
}

static void test_RtlRealPredecessor(void)
{
    /*       3
     *     /   \
     *    1     5
     *   / \   / \
     *  0   2 4   6
     */
    static const struct splay_index splay_indices[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
    };
    static const int expected_predecessors[] = {-1, 0, 1, 2, 3, 4, 5};
    RTL_SPLAY_LINKS links[7], *predecessor;
    unsigned int i;

    if (!pRtlRealPredecessor)
    {
        win_skip("RtlRealPredecessor is unavailable.\n");
        return;
    }

    init_splay_indices(links, ARRAY_SIZE(links), splay_indices, ARRAY_SIZE(splay_indices));
    for (i = 0; i < ARRAY_SIZE(expected_predecessors); i++)
    {
        winetest_push_context("%d", i);

        predecessor = pRtlRealPredecessor(&links[i]);
        if (expected_predecessors[i] == -1)
            ok(!predecessor, "Expected NULL, got unexpected %d.\n", (int)(predecessor - links));
        else
            ok(predecessor == &links[expected_predecessors[i]], "Expected %d, got unexpected %d.\n",
               expected_predecessors[i], (int)(predecessor ? predecessor - links : -1));

        winetest_pop_context();
    }
}

static void test_RtlRealSuccessor(void)
{
    /*       3
     *     /   \
     *    1     5
     *   / \   / \
     *  0   2 4   6
     */
    static const struct splay_index splay_indices[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
    };
    static const int expected_successors[] = {1, 2, 3, 4, 5, 6, -1};
    RTL_SPLAY_LINKS links[7], *successor;
    unsigned int i;

    if (!pRtlRealSuccessor)
    {
        win_skip("RtlRealSuccessor is unavailable.\n");
        return;
    }

    init_splay_indices(links, ARRAY_SIZE(links), splay_indices, ARRAY_SIZE(splay_indices));
    for (i = 0; i < ARRAY_SIZE(expected_successors); i++)
    {
        winetest_push_context("%d", i);

        successor = pRtlRealSuccessor(&links[i]);
        if (expected_successors[i] == -1)
            ok(!successor, "Expected NULL, got unexpected %d.\n", (int)(successor - links));
        else
            ok(successor == &links[expected_successors[i]], "Expected %d, got unexpected %d.\n",
               expected_successors[i], (int)(successor ? successor - links : -1));

        winetest_pop_context();
    }
}

static void test_RtlSplay(void)
{
    /*      3
     *    /   \
     *   1     5
     *  / \   / \
     * 0   2 4   6
     */
    static const struct splay_index splay_indices[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      0
     *       \
     *        1
     *         \
     *          3
     *         / \
     *        2   5
     *           / \
     *          4   6
     */
    static const struct splay_index splay0[] =
    {
        {0, -1, 1},
        {1, -1, 3},
        {3, 2, 5},
        {5, 4, 6},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      1
     *     / \
     *    0   3
     *       / \
     *      2   5
     *         / \
     *        4   6
     */
    static const struct splay_index splay1[] =
    {
        {1, 0, 3},
        {3, 2, 5},
        {5, 4, 6},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      2
     *     / \
     *    1   3
     *   /     \
     *  0       5
     *         / \
     *        4   6
     */
    static const struct splay_index splay2[] =
    {
        {2, 1, 3},
        {1, 0, -1},
        {3, -1, 5},
        {5, 4, 6},
        {0, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      3
     *    /   \
     *   1     5
     *  / \   / \
     * 0   2 4   6
     */
    static const struct splay_index splay3[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*       4
     *      / \
     *     3   5
     *    /     \
     *   1       6
     *  / \
     * 0   2
     */
    static const struct splay_index splay4[] =
    {
        {4, 3, 5},
        {3, 1, -1},
        {5, -1, 6},
        {1, 0, 2},
        {0, -1, -1},
        {2, -1, -1},
        {6, -1, -1},
    };
    /*       5
     *      / \
     *     3   6
     *    / \
     *   1   4
     *  / \
     * 0   2
     */
    static const struct splay_index splay5[] =
    {
        {5, 3, 6},
        {3, 1, 4},
        {1, 0, 2},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*         6
     *        /
     *       5
     *      /
     *     3
     *    / \
     *   1   4
     *  / \
     * 0   2
     */
    static const struct splay_index splay6[] =
    {
        {6, 5, -1},
        {5, 3, -1},
        {3, 1, 4},
        {1, 0, 2},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
    };
    RTL_SPLAY_LINKS links[7], *root;
    static const struct
    {
        const struct splay_index *indices;
        unsigned int indices_count;
    }
    expected_indices[] =
    {
        {splay0, ARRAY_SIZE(splay0)},
        {splay1, ARRAY_SIZE(splay1)},
        {splay2, ARRAY_SIZE(splay2)},
        {splay3, ARRAY_SIZE(splay3)},
        {splay4, ARRAY_SIZE(splay4)},
        {splay5, ARRAY_SIZE(splay5)},
        {splay6, ARRAY_SIZE(splay6)},
    };
    unsigned int i;

    if (!pRtlSplay)
    {
        win_skip("RtlSplay is unavailable.\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(expected_indices); i++)
    {
        winetest_push_context("%d", i);

        init_splay_indices(links, ARRAY_SIZE(links), splay_indices, ARRAY_SIZE(splay_indices));
        root = pRtlSplay(&links[i]);
        expect_splay_indices(links, root, expected_indices[i].indices, expected_indices[i].indices_count);

        winetest_pop_context();
    }
}

static void test_RtlDeleteNoSplay(void)
{
    /*      3
     *    /   \
     *   1     5
     *  / \   / \
     * 0   2 4   6
     */
    static const struct splay_index splay_indices[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      3
     *    /   \
     *   1     5
     *    \   / \
     *     2 4   6
     */
    static const struct splay_index delete0[] =
    {
        {3, 1, 5},
        {1, -1, 2},
        {5, 4, 6},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      3
     *    /   \
     *   0     5
     *    \   / \
     *     2 4   6
     */
    static const struct splay_index delete1[] =
    {
        {3, 0, 5},
        {0, -1, 2},
        {5, 4, 6},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      3
     *     / \
     *    1   5
     *   /   / \
     *  0   4   6
     */
    static const struct splay_index delete2[] =
    {
        {3, 1, 5},
        {1, 0, -1},
        {5, 4, 6},
        {0, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      2
     *     / \
     *    1   5
     *   /   / \
     *  0   4   6
     */
    static const struct splay_index delete3[] =
    {
        {2, 1, 5},
        {1, 0, -1},
        {5, 4, 6},
        {0, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*     3
     *    / \
     *   1   5
     *  / \   \
     * 0   2   6
     */
    static const struct splay_index delete4[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, -1, 6},
        {0, -1, -1},
        {2, -1, -1},
        {6, -1, -1},
    };
    /*     3
     *    / \
     *   1   4
     *  / \   \
     * 0   2   6
     */
    static const struct splay_index delete5[] =
    {
        {3, 1, 4},
        {1, 0, 2},
        {4, -1, 6},
        {0, -1, -1},
        {2, -1, -1},
        {6, -1, -1},
    };
    /*      3
     *    /   \
     *   1     5
     *  / \   /
     * 0   2 4
     */
    static const struct splay_index delete6[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, -1},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
    };
    RTL_SPLAY_LINKS links[7], *root;
    static const struct
    {
        const struct splay_index *indices;
        unsigned int index_count;
    }
    expected_indices[] =
    {
        {delete0, ARRAY_SIZE(delete0)},
        {delete1, ARRAY_SIZE(delete1)},
        {delete2, ARRAY_SIZE(delete2)},
        {delete3, ARRAY_SIZE(delete3)},
        {delete4, ARRAY_SIZE(delete4)},
        {delete5, ARRAY_SIZE(delete5)},
        {delete6, ARRAY_SIZE(delete6)},
    };
    unsigned int i;

    if (!pRtlDeleteNoSplay)
    {
        win_skip("RtlDeleteNoSplay is unavailable.\n");
        return;
    }

    for (i = 0; i < ARRAY_SIZE(expected_indices); i++)
    {
        winetest_push_context("%d", i);

        init_splay_indices(links, ARRAY_SIZE(links), splay_indices, ARRAY_SIZE(splay_indices));
        root = &links[expected_indices[i].indices[0].parent_index];
        pRtlDeleteNoSplay(&links[i], &root);
        expect_splay_indices(links, root, expected_indices[i].indices, expected_indices[i].index_count);

        winetest_pop_context();
    }

    /* Test that root should be NULL when the splay tree is empty */
    RtlInitializeSplayLinks(&links[0]);
    pRtlDeleteNoSplay(&links[0], &root);
    ok(root == NULL, "Got unexpected root.\n");
}

static void test_RtlDelete(void)
{
    /*      3
     *    /   \
     *   1     5
     *  / \   / \
     * 0   2 4   6
     */
    static const struct splay_index splay_indices[] =
    {
        {3, 1, 5},
        {1, 0, 2},
        {5, 4, 6},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      1
     *       \
     *        3
     *       / \
     *      2   5
     *         / \
     *        4   6
     */
    static const struct splay_index delete0[] =
    {
        {1, -1, 3},
        {3, 2, 5},
        {5, 4, 6},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      0
     *       \
     *        3
     *       / \
     *      2   5
     *         / \
     *        4   6
     */
    static const struct splay_index delete1[] =
    {
        {0, -1, 3},
        {3, 2, 5},
        {5, 4, 6},
        {2, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      1
     *     / \
     *    0   3
     *         \
     *          5
     *         / \
     *        4   6
     */
    static const struct splay_index delete2[] =
    {
        {1, 0, 3},
        {3, -1, 5},
        {5, 4, 6},
        {0, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*      1
     *     / \
     *    0   2
     *         \
     *          5
     *         / \
     *        4   6
     */
    static const struct splay_index delete3[] =
    {
        {1, 0, 2},
        {2, -1, 5},
        {5, 4, 6},
        {0, -1, -1},
        {4, -1, -1},
        {6, -1, -1},
    };
    /*       5
     *      / \
     *     3   6
     *    /
     *   1
     *  / \
     * 0   2
     */
    static const struct splay_index delete4[] =
    {
        {5, 3, 6},
        {3, 1, -1},
        {1, 0, 2},
        {0, -1, -1},
        {2, -1, -1},
        {6, -1, -1},
    };
    /*       4
     *      / \
     *     3   6
     *    /
     *   1
     *  / \
     * 0   2
     */
    static const struct splay_index delete5[] =
    {
        {4, 3, 6},
        {3, 1, -1},
        {1, 0, 2},
        {0, -1, -1},
        {2, -1, -1},
        {6, -1, -1},
    };
    /*       5
     *      /
     *     3
     *    / \
     *   1   4
     *  / \
     * 0   2
     */
    static const struct splay_index delete6[] =
    {
        {5, 3, -1},
        {3, 1, 4},
        {1, 0, 2},
        {0, -1, -1},
        {2, -1, -1},
        {4, -1, -1},
    };
    RTL_SPLAY_LINKS links[7], *root;
    static const struct
    {
        const struct splay_index *indices;
        unsigned int index_count;
    }
    expected_indices[] =
    {
        {delete0, ARRAY_SIZE(delete0)},
        {delete1, ARRAY_SIZE(delete1)},
        {delete2, ARRAY_SIZE(delete2)},
        {delete3, ARRAY_SIZE(delete3)},
        {delete4, ARRAY_SIZE(delete4)},
        {delete5, ARRAY_SIZE(delete5)},
        {delete6, ARRAY_SIZE(delete6)},
    };
    unsigned int i;

    if (!pRtlDelete)
    {
        win_skip("RtlDelete is unavailable.\n");
        return;
    }
    for (i = 0; i < ARRAY_SIZE(expected_indices); i++)
    {
        winetest_push_context("%d", i);

        init_splay_indices(links, ARRAY_SIZE(links), splay_indices, ARRAY_SIZE(splay_indices));

        root = pRtlDelete(&links[i]);
        expect_splay_indices(links, root, expected_indices[i].indices, expected_indices[i].index_count);

        winetest_pop_context();
    }

    /* Test that root should be NULL when the splay tree is empty */
    RtlInitializeSplayLinks(&links[0]);
    root = pRtlDelete(&links[0]);
    ok(root == NULL, "Got unexpected root.\n");
}

/* data is a place holder to align stored data on a 8 byte boundary */
struct rtl_generic_table_entry
{
    RTL_SPLAY_LINKS splay_links;
    LIST_ENTRY list_entry;
    LONGLONG data;
};

static void *get_data_from_list_entry(LIST_ENTRY *list_entry)
{
    return (unsigned char *)list_entry + FIELD_OFFSET(struct rtl_generic_table_entry, data)
        - FIELD_OFFSET(struct rtl_generic_table_entry, list_entry);
}

static RTL_SPLAY_LINKS *get_splay_links_from_data(void *data)
{
    return (RTL_SPLAY_LINKS *)((unsigned char *)data - FIELD_OFFSET(struct rtl_generic_table_entry, data));
}

static LIST_ENTRY *get_list_entry_from_data(void *data)
{
    return (LIST_ENTRY *)((unsigned char *)data - FIELD_OFFSET(struct rtl_generic_table_entry, data)
        + FIELD_OFFSET(struct rtl_generic_table_entry, list_entry));
}

static RTL_GENERIC_COMPARE_RESULTS WINAPI generic_compare_proc(RTL_GENERIC_TABLE *table, void *p1, void *p2)
{
    int *value1 = p1, *value2 = p2;

    if (*value1 < *value2)
        return GenericLessThan;
    else if (*value1 > *value2)
        return GenericGreaterThan;
    else
        return GenericEqual;
}

static void * WINAPI generic_allocate_proc(RTL_GENERIC_TABLE *table, CLONG size)
{
    CLONG *last_allocated = table->TableContext;

    if (last_allocated)
        *last_allocated = size;
    return malloc(size);
}

static void WINAPI generic_free_proc(RTL_GENERIC_TABLE *table, void *ptr)
{
    free(ptr);
}

static RTL_GENERIC_COMPARE_RESULTS WINAPI avl_compare_proc(RTL_AVL_TABLE *table, void *p1, void *p2)
{
    int *value1 = p1, *value2 = p2;

    if (*value1 < *value2) return GenericLessThan;
    if (*value1 > *value2) return GenericGreaterThan;
    return GenericEqual;
}

static void * WINAPI avl_allocate_proc(RTL_AVL_TABLE *table, LONG size)
{
    return malloc(size);
}

static void WINAPI avl_free_proc(RTL_AVL_TABLE *table, void *ptr)
{
    free(ptr);
}

static unsigned int validate_avl_tree(RTL_BALANCED_LINKS *links, RTL_BALANCED_LINKS *parent,
                                      int *previous, unsigned int *count)
{
    unsigned int left_depth, right_depth;
    int value, expected_balance;

    if (!links) return 0;
    ok(links->Parent == parent, "Got parent %p, expected %p.\n", links->Parent, parent);
    left_depth = validate_avl_tree(links->LeftChild, links, previous, count);
    value = *(int *)(links + 1);
    if (*count) ok(*previous < value, "Values are out of order: %d then %d.\n", *previous, value);
    *previous = value;
    (*count)++;
    right_depth = validate_avl_tree(links->RightChild, links, previous, count);
    expected_balance = (int)right_depth - (int)left_depth;
    ok(expected_balance >= -1 && expected_balance <= 1,
       "Tree is not balanced at %d: left depth %u, right depth %u.\n",
       value, left_depth, right_depth);
    ok(links->Balance == expected_balance, "Got balance %d for %d, expected %d.\n",
       links->Balance, value, expected_balance);
    return 1 + max(left_depth, right_depth);
}

static void test_RtlEnumerateGenericTableAvl(void)
{
    struct avl_entry
    {
        RTL_BALANCED_LINKS links;
        int value;
    } entries[3];
    RTL_AVL_TABLE table;
    void *restart_key;
    int *ret;

    if (!pRtlInitializeGenericTableAvl || !pRtlEnumerateGenericTableAvl ||
        !pRtlEnumerateGenericTableWithoutSplayingAvl)
    {
        win_skip("Generic AVL table functions are unavailable.\n");
        return;
    }

    memset(&table, 0xff, sizeof(table));
    pRtlInitializeGenericTableAvl(&table, avl_compare_proc, avl_allocate_proc,
                                  avl_free_proc, (void *)0xdeadbeef);
    ok(table.BalancedRoot.Parent == &table.BalancedRoot, "Got unexpected root parent %p.\n",
       table.BalancedRoot.Parent);
    ok(!table.BalancedRoot.LeftChild, "Got unexpected root left child %p.\n",
       table.BalancedRoot.LeftChild);
    ok(!table.BalancedRoot.RightChild, "Got unexpected root right child %p.\n",
       table.BalancedRoot.RightChild);
    ok(!table.OrderedPointer, "Got unexpected ordered pointer %p.\n", table.OrderedPointer);
    ok(!table.WhichOrderedElement, "Got unexpected ordered element %lu.\n", table.WhichOrderedElement);
    ok(!table.NumberGenericTableElements, "Got unexpected element count %lu.\n",
       table.NumberGenericTableElements);
    ok(!table.DepthOfTree, "Got unexpected tree depth %lu.\n", table.DepthOfTree);
    ok(!table.RestartKey, "Got unexpected restart key %p.\n", table.RestartKey);
    ok(!table.DeleteCount, "Got unexpected delete count %lu.\n", table.DeleteCount);
    ok(table.CompareRoutine == avl_compare_proc, "Got unexpected compare routine.\n");
    ok(table.AllocateRoutine == avl_allocate_proc, "Got unexpected allocate routine.\n");
    ok(table.FreeRoutine == avl_free_proc, "Got unexpected free routine.\n");
    ok(table.TableContext == (void *)0xdeadbeef, "Got unexpected table context %p.\n",
       table.TableContext);

    table.RestartKey = (void *)0xdeadbeef;
    ret = pRtlEnumerateGenericTableAvl(&table, TRUE);
    ok(!ret, "Got unexpected element %p.\n", ret);
    ok(!table.RestartKey, "Got unexpected restart key %p.\n", table.RestartKey);

    memset(entries, 0, sizeof(entries));
    entries[0].value = 1;
    entries[1].value = 2;
    entries[2].value = 3;
    table.BalancedRoot.RightChild = &entries[1].links;
    entries[1].links.Parent = &table.BalancedRoot;
    entries[1].links.LeftChild = &entries[0].links;
    entries[1].links.RightChild = &entries[2].links;
    entries[0].links.Parent = &entries[1].links;
    entries[2].links.Parent = &entries[1].links;
    table.NumberGenericTableElements = ARRAY_SIZE(entries);

    restart_key = NULL;
    ret = pRtlEnumerateGenericTableWithoutSplayingAvl(&table, &restart_key);
    ok(ret == &entries[0].value, "Got unexpected first element %p.\n", ret);
    ok(restart_key == &entries[0].links, "Got unexpected restart key %p.\n", restart_key);
    ret = pRtlEnumerateGenericTableWithoutSplayingAvl(&table, &restart_key);
    ok(ret == &entries[1].value, "Got unexpected second element %p.\n", ret);
    ret = pRtlEnumerateGenericTableWithoutSplayingAvl(&table, &restart_key);
    ok(ret == &entries[2].value, "Got unexpected third element %p.\n", ret);
    ret = pRtlEnumerateGenericTableWithoutSplayingAvl(&table, &restart_key);
    ok(!ret, "Got unexpected element %p.\n", ret);
    ok(restart_key == &entries[2].links, "Got unexpected final restart key %p.\n", restart_key);

    ret = pRtlEnumerateGenericTableAvl(&table, TRUE);
    ok(ret == &entries[0].value, "Got unexpected first restarted element %p.\n", ret);
    ret = pRtlEnumerateGenericTableAvl(&table, FALSE);
    ok(ret == &entries[1].value, "Got unexpected second restarted element %p.\n", ret);
    ret = pRtlEnumerateGenericTableAvl(&table, FALSE);
    ok(ret == &entries[2].value, "Got unexpected third restarted element %p.\n", ret);
    ret = pRtlEnumerateGenericTableAvl(&table, FALSE);
    ok(!ret, "Got unexpected element %p.\n", ret);

    if (pRtlInsertElementGenericTableAvl && pRtlDeleteElementGenericTableAvl &&
        pRtlIsGenericTableEmptyAvl &&
        pRtlLookupElementGenericTableAvl && pRtlNumberGenericTableElementsAvl)
    {
        static const int values[] = {30, 20, 10, 40, 50, 25, 27, 5, 4, 35, 45, 60, 55};
        static const int delete_values[] = {4, 30, 20, 55, 10, 40, 27, 60, 5, 35, 25, 45, 50};
        unsigned int i, count, depth;
        BOOLEAN new_element;
        int previous, missing = 99;

        pRtlInitializeGenericTableAvl(&table, avl_compare_proc, avl_allocate_proc,
                                      avl_free_proc, NULL);
        ok(pRtlIsGenericTableEmptyAvl(&table), "New table is not empty.\n");
        for (i = 0; i < ARRAY_SIZE(values); i++)
        {
            new_element = 0xcc;
            ret = pRtlInsertElementGenericTableAvl(&table, (void *)&values[i], sizeof(values[i]),
                                                    &new_element);
            ok(ret && *ret == values[i], "Got result %p for %d.\n", ret, values[i]);
            ok(new_element == TRUE, "Element %d was not reported new.\n", values[i]);
            ok(pRtlNumberGenericTableElementsAvl(&table) == i + 1,
               "Got element count %lu after insert %u.\n",
               pRtlNumberGenericTableElementsAvl(&table), i);
            previous = 0;
            count = 0;
            depth = validate_avl_tree(table.BalancedRoot.RightChild, &table.BalancedRoot,
                                      &previous, &count);
            ok(count == i + 1, "Validated %u elements, expected %u.\n", count, i + 1);
            ok(table.DepthOfTree == depth, "Got depth %lu, expected %u.\n",
               table.DepthOfTree, depth);
        }
        ok(!pRtlIsGenericTableEmptyAvl(&table), "Populated table is empty.\n");

        for (i = 0; i < ARRAY_SIZE(values); i++)
        {
            ret = pRtlLookupElementGenericTableAvl(&table, (void *)&values[i]);
            ok(ret && *ret == values[i], "Lookup returned %p for %d.\n", ret, values[i]);
        }
        ok(!pRtlLookupElementGenericTableAvl(&table, &missing), "Found missing value.\n");

        new_element = 0xcc;
        ret = pRtlInsertElementGenericTableAvl(&table, (void *)&values[3], sizeof(values[3]),
                                                &new_element);
        ok(ret && *ret == values[3], "Duplicate insert returned %p.\n", ret);
        ok(new_element == FALSE, "Duplicate element was reported new.\n");
        ok(pRtlNumberGenericTableElementsAvl(&table) == ARRAY_SIZE(values),
           "Duplicate changed element count to %lu.\n",
           pRtlNumberGenericTableElementsAvl(&table));

        ret = pRtlEnumerateGenericTableAvl(&table, TRUE);
        ok(ret && *ret == delete_values[0], "Got unexpected first enumerated value.\n");
        for (i = 0; i < ARRAY_SIZE(delete_values); i++)
        {
            ok(pRtlDeleteElementGenericTableAvl(&table, (void *)&delete_values[i]),
               "Failed to delete %d.\n", delete_values[i]);
            ok(!pRtlLookupElementGenericTableAvl(&table, (void *)&delete_values[i]),
               "Deleted value %d is still present.\n", delete_values[i]);
            ok(pRtlNumberGenericTableElementsAvl(&table) == ARRAY_SIZE(delete_values) - i - 1,
               "Got element count %lu after delete %u.\n",
               pRtlNumberGenericTableElementsAvl(&table), i);
            previous = 0;
            count = 0;
            depth = validate_avl_tree(table.BalancedRoot.RightChild, &table.BalancedRoot,
                                      &previous, &count);
            ok(count == ARRAY_SIZE(delete_values) - i - 1,
               "Validated %u elements after delete %u.\n", count, i);
            ok(table.DepthOfTree == depth, "Got depth %lu after delete, expected %u.\n",
               table.DepthOfTree, depth);
            if (!i)
            {
                ret = pRtlEnumerateGenericTableAvl(&table, FALSE);
                ok(ret && *ret == 5, "Enumeration did not continue after deleting restart key.\n");
            }
        }
        ok(pRtlIsGenericTableEmptyAvl(&table), "Deleted table is not empty.\n");
        ok(!table.BalancedRoot.RightChild, "Deleted table still has root %p.\n",
           table.BalancedRoot.RightChild);
        ok(!pRtlDeleteElementGenericTableAvl(&table, &missing),
           "Deleted missing value from empty table.\n");
    }
    else
        win_skip("Generic AVL table mutation functions are unavailable.\n");
}

static void test_RtlInitializeGenericTable(void)
{
    RTL_GENERIC_TABLE table;

    if (!pRtlInitializeGenericTable)
    {
        win_skip("RtlInitializeGenericTable is unavailable.\n");
        return;
    }

    memset(&table, 0xff, sizeof(table));
    pRtlInitializeGenericTable(&table, generic_compare_proc, generic_allocate_proc,
                               generic_free_proc, (void *)0xdeadbeef);
    ok(!table.TableRoot, "Got unexpected TableRoot.\n");
    ok(table.InsertOrderList.Flink == &table.InsertOrderList, "Got unexpected InsertOrderList.Flink.\n");
    ok(table.InsertOrderList.Blink == &table.InsertOrderList, "Got unexpected InsertOrderList.Blink.\n");
    ok(table.OrderedPointer == &table.InsertOrderList, "Got unexpected OrderedPointer.\n");
    ok(!table.NumberGenericTableElements, "Got unexpected NumberGenericTableElements.\n");
    ok(!table.WhichOrderedElement, "Got unexpected WhichOrderedElement.\n");
    ok(table.CompareRoutine == generic_compare_proc, "Got unexpected CompareRoutine.\n");
    ok(table.AllocateRoutine == generic_allocate_proc, "Got unexpected AllocateRoutine.\n");
    ok(table.FreeRoutine == generic_free_proc, "Got unexpected FreeRoutine.\n");
    ok(table.TableContext == (void *)0xdeadbeef, "Got unexpected TableContext.\n");
}

static void test_RtlNumberGenericTableElements(void)
{
    RTL_GENERIC_TABLE table;
    ULONG count;

    if (!pRtlNumberGenericTableElements)
    {
        win_skip("RtlNumberGenericTableElements is unavailable.\n");
        return;
    }

    table.NumberGenericTableElements = 0xdeadbeef;
    count = pRtlNumberGenericTableElements(&table);
    ok(count == table.NumberGenericTableElements, "Got unexpected count.\n");
}

static void test_RtlIsGenericTableEmpty(void)
{
    RTL_GENERIC_TABLE table;
    BOOLEAN empty;

    if (!pRtlIsGenericTableEmpty)
    {
        win_skip("RtlIsGenericTableEmpty is unavailable.\n");
        return;
    }

    /* Test that RtlIsGenericTableEmpty() uses TableRoot to check if a generic table is empty */
    table.TableRoot = NULL;
    table.NumberGenericTableElements = 1;
    empty = pRtlIsGenericTableEmpty(&table);
    ok(empty, "Expected empty.\n");

    table.TableRoot = (RTL_SPLAY_LINKS *)1;
    table.NumberGenericTableElements = 0;
    empty = pRtlIsGenericTableEmpty(&table);
    ok(!empty, "Expected not empty.\n");
}

static void test_RtlInsertElementGenericTable(void)
{
    static const int elements[] = {1, 9, 5, 4, 7, 2, 3, 8, 6};
    int i, value, *ret, *first_ret = NULL, *last_ret = NULL;
    ULONG count, size, last_allocated;
    BOOLEAN new_element, success;
    RTL_GENERIC_TABLE table;
    LIST_ENTRY *entry;

    if (!pRtlInsertElementGenericTable)
    {
        win_skip("RtlInsertElementGenericTable is unavailable.\n");
        return;
    }

    pRtlInitializeGenericTable(&table, generic_compare_proc, generic_allocate_proc,
                               generic_free_proc, (void *)&last_allocated);

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
        ok(ret && *ret == value, "Got unexpected pointer.\n");
        ok(new_element, "Expected new element.\n");
        ok(table.TableRoot == get_splay_links_from_data(ret), "Got unexpected TableRoot.\n");

        if (i == 0)
            first_ret = ret;
        if (i == ARRAY_SIZE(elements) - 1)
            last_ret = ret;
    }

    count = pRtlNumberGenericTableElements(&table);
    ok(count == ARRAY_SIZE(elements), "Got unexpected count %ld.\n", count);

    /* Test that the allocated memory includes a RTL_SPLAY_LINKS and a LIST_ENTRY header. The data
     * is aligned on a 8 byte boundary */
    size = FIELD_OFFSET(struct rtl_generic_table_entry, data) + sizeof(value);
    ok(last_allocated == size, "Expected %lu, got %lu.\n", size, last_allocated);

    /* Check that InsertOrderList points to a doubly linked list of elements in insertion order */
    ok(table.InsertOrderList.Flink == get_list_entry_from_data(first_ret), "Got unexpected Flink.\n");
    ok(table.InsertOrderList.Blink == get_list_entry_from_data(last_ret), "Got unexpected Blink.\n");
    for (i = 0, entry = table.InsertOrderList.Flink; entry->Flink != table.InsertOrderList.Flink;
         i++, entry = entry->Flink)
    {
        ret = (int *)get_data_from_list_entry(entry);
        ok(*ret == elements[i], "Got unexpected pointer, value %d.\n", *ret);
    }
    ok(i == ARRAY_SIZE(elements), "Got unexpected index %d.\n", i);
    for (i = ARRAY_SIZE(elements) - 1, entry = table.InsertOrderList.Blink;
         entry->Blink != table.InsertOrderList.Blink; i--, entry = entry->Blink)
    {
        ret = (int *)get_data_from_list_entry(entry);
        ok(*ret == elements[i], "Got unexpected pointer, value %d.\n", *ret);
    }
    ok(i == -1, "Got unexpected index %d.\n", i);

    /* Insert the same element again */
    ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
    ok(ret && *ret == value, "Got unexpected pointer.\n");
    ok(!new_element, "Expected old element.\n");

    count = pRtlNumberGenericTableElements(&table);
    ok(count == ARRAY_SIZE(elements), "Got unexpected count %ld.\n", count);

    /* Insert a new element with new_element pointer being NULL */
    value = 0;
    ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), NULL);
    ok(ret && ret != &value && *ret == 0, "Got unexpected pointer.\n");

    count = pRtlNumberGenericTableElements(&table);
    ok(count == ARRAY_SIZE(elements) + 1, "Got unexpected count %ld.\n", count);

    success = pRtlDeleteElementGenericTable(&table, &value);
    ok(success, "RtlDeleteElementGenericTable failed.\n");

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        success = pRtlDeleteElementGenericTable(&table, &value);
        ok(success, "RtlDeleteElementGenericTable failed.\n");
    }
}

static void test_RtlDeleteElementGenericTable(void)
{
    static const int elements[] = {1, 9, 5, 4, 7, 2, 3, 8, 6};
    BOOLEAN success, new_element, empty;
    RTL_GENERIC_TABLE table;
    int i, value, *ret;

    if (!pRtlDeleteElementGenericTable)
    {
        win_skip("RtlDeleteElementGenericTable is unavailable.\n");
        return;
    }

    pRtlInitializeGenericTable(&table, generic_compare_proc, generic_allocate_proc, generic_free_proc, NULL);

    success = pRtlDeleteElementGenericTable(&table, NULL);
    ok(!success, "Got unexpected pointer.\n");

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
        ok(ret && *ret == value, "Got unexpected pointer.\n");
        ok(new_element, "Expected new element.\n");
    }

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        success = pRtlDeleteElementGenericTable(&table, &value);
        ok(success, "RtlDeleteElementGenericTable failed.\n");
        ok(table.NumberGenericTableElements == ARRAY_SIZE(elements) - i - 1,
           "Got unexpected NumberGenericTableElements %lu.\n", table.NumberGenericTableElements);
    }

    empty = pRtlIsGenericTableEmpty(&table);
    ok(empty, "Expected empty.\n");

    /* Delete non-existent element */
    value = elements[0];
    success = pRtlDeleteElementGenericTable(&table, &value);
    ok(!success, "RtlDeleteElementGenericTable succeeded.\n");
}

static void test_RtlLookupElementGenericTable(void)
{
    static const int elements[] = {1, 9, 5, 4, 7, 2, 3, 8, 6};
    BOOLEAN new_element, success;
    RTL_GENERIC_TABLE table;
    int i, value, *ret;

    if (!pRtlLookupElementGenericTable)
    {
        win_skip("RtlLookupElementGenericTable is unavailable.\n");
        return;
    }

    pRtlInitializeGenericTable(&table, generic_compare_proc, generic_allocate_proc, generic_free_proc, NULL);

    ret = pRtlLookupElementGenericTable(&table, NULL);
    ok(!ret, "Got unexpected pointer.\n");

    value = 1;
    ret = pRtlLookupElementGenericTable(&table, &value);
    ok(!ret, "Got unexpected pointer.\n");

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
        ok(ret && *ret == value, "Got unexpected pointer.\n");
        ok(new_element, "Expected new element.\n");
    }

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        ret = pRtlLookupElementGenericTable(&table, &value);
        ok(ret && *ret == value, "Got unexpected pointer.\n");
        ok(table.TableRoot == get_splay_links_from_data(ret), "Got unexpected TableRoot.\n");
    }

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        success = pRtlDeleteElementGenericTable(&table, &value);
        ok(success, "RtlDeleteElementGenericTable failed.\n");
    }
}

static void test_RtlEnumerateGenericTableWithoutSplaying(void)
{
    static const int elements[] = {1, 9, 5, 4, 7, 2, 3, 8, 6};
    static const int expected_elements[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    RTL_SPLAY_LINKS *old_table_root;
    BOOLEAN new_element, success;
    RTL_GENERIC_TABLE table;
    int i, value, *ret;
    void *restart_key;

    if (!pRtlEnumerateGenericTableWithoutSplaying)
    {
        win_skip("RtlEnumerateGenericTableWithoutSplaying is unavailable.\n");
        return;
    }

    pRtlInitializeGenericTable(&table, generic_compare_proc, generic_allocate_proc, generic_free_proc, NULL);

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
        ok(ret && *ret == value, "Got unexpected pointer.\n");
        ok(new_element, "Expected new element.\n");
    }

    /* Test that restart key is a pointer to RTL_SPLAY_LINKS pointing to returned element */
    restart_key = NULL;
    ret = pRtlEnumerateGenericTableWithoutSplaying(&table, &restart_key);
    ok(ret && *ret == expected_elements[0], "Expected %d at %d, got %d.\n",
       expected_elements[0], 0, ret ? *ret : -1);
    ok(restart_key == get_splay_links_from_data(ret), "Got unexpected restart key %p.\n", restart_key);

    /* Test enumeration */
    old_table_root = table.TableRoot;
    restart_key = NULL;
    for (i = 0, ret = pRtlEnumerateGenericTableWithoutSplaying(&table, &restart_key); ret != NULL;
         ret = pRtlEnumerateGenericTableWithoutSplaying(&table, &restart_key), i++)
    {
        ok(ret && *ret == expected_elements[i], "Expected %d at %d, got %d.\n",
           expected_elements[i], i, ret ? *ret : -1);
        ok(table.TableRoot == old_table_root, "Got unexpected TableRoot.\n");
    }
    ok(i == ARRAY_SIZE(elements), "Got unexpected index %d.\n", i);

    /* Test restarting enumeration */
    restart_key = NULL;
    for (i = 0, ret = pRtlEnumerateGenericTableWithoutSplaying(&table, &restart_key); ret != NULL;
         ret = pRtlEnumerateGenericTableWithoutSplaying(&table, &restart_key), i++)
    {
        ok(ret && *ret == expected_elements[i], "Expected %d at %d, got %d.\n",
           expected_elements[i], i, ret ? *ret : -1);
        ok(table.TableRoot == old_table_root, "Got unexpected TableRoot.\n");
    }
    ok(i == ARRAY_SIZE(elements), "Got unexpected index %d.\n", i);

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        success = pRtlDeleteElementGenericTable(&table, &value);
        ok(success, "RtlDeleteElementGenericTable %d failed.\n", elements[i]);
    }
}

static void test_RtlEnumerateGenericTable(void)
{
    static const int elements[] = {1, 9, 5, 4, 7, 2, 3, 8, 6};
    static const int expected_elements[] = {1, 2, 3, 4, 5, 6, 7, 8, 9};
    int i, j, value, *ret, *first_ret = NULL, *last_ret = NULL;
    BOOLEAN success, new_element;
    RTL_GENERIC_TABLE table;
    LIST_ENTRY *entry;

    if (!pRtlEnumerateGenericTable)
    {
        win_skip("RtlEnumerateGenericTable is unavailable.\n");
        return;
    }

    pRtlInitializeGenericTable(&table, generic_compare_proc, generic_allocate_proc, generic_free_proc, NULL);

    ret = pRtlEnumerateGenericTable(&table, TRUE);
    ok(!ret, "Got unexpected pointer.\n");

    ret = pRtlEnumerateGenericTable(&table, FALSE);
    ok(!ret, "Got unexpected pointer.\n");

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
        ok(ret && *ret == value, "Got unexpected pointer.\n");
        ok(new_element, "Expected new element.\n");

        if (i == 0)
            first_ret = ret;
        if (i == ARRAY_SIZE(elements) - 1)
            last_ret = ret;
    }

    /* Test enumeration */
    for (i = 0, ret = pRtlEnumerateGenericTable(&table, TRUE); ret != NULL;
         ret = pRtlEnumerateGenericTable(&table, FALSE), i++)
    {
        ok(ret && *ret == expected_elements[i], "Expected %d at %d, got %d.\n",
           expected_elements[i], i, ret ? *ret : -1);
        ok(table.TableRoot == get_splay_links_from_data(ret), "Got unexpected TableRoot.\n");

        /* Test that RtlEnumerateGenericTable() doesn't touch WhichOrderedElement, OrderedPointer and
         * InsertOrderList. Additional tests show that RtlEnumerateGenericTable() uses TableRoot
         * to keep track of enumeration status. This also means that if other functions that change
         * TableRoot get used during enumerations, RtlEnumerateGenericTable() won't be able to find
         * the correct next element, which is also the case on Windows */
        ok(table.WhichOrderedElement == 0, "Got unexpected WhichOrderedElement.\n");
        ok(table.OrderedPointer == &table.InsertOrderList, "Got unexpected OrderedPointer.\n");
        ok(table.InsertOrderList.Flink == get_list_entry_from_data(first_ret), "Got unexpected Flink.\n");
        ok(table.InsertOrderList.Blink == get_list_entry_from_data(last_ret), "Got unexpected Blink.\n");
        for (j = 0, entry = table.InsertOrderList.Flink; entry->Flink != table.InsertOrderList.Flink;
             j++, entry = entry->Flink)
        {
            ret = (int *)get_data_from_list_entry(entry);
            ok(*ret == elements[j], "Got unexpected pointer, value %d.\n", *ret);
        }
        ok(table.TableContext == NULL, "Got unexpected TableContext.\n");
    }
    ok(i == ARRAY_SIZE(elements), "Got unexpected index %d.\n", i);

    /* Test restarting enumeration */
    for (i = 0, ret = pRtlEnumerateGenericTable(&table, TRUE); ret != NULL;
         ret = pRtlEnumerateGenericTable(&table, FALSE), i++)
    {
        ok(ret && *ret == expected_elements[i], "Expected %d at %d, got %d.\n", expected_elements[i],
           i, ret ? *ret : -1);
        ok(table.TableRoot == get_splay_links_from_data(ret), "Got unexpected TableRoot.\n");
    }
    ok(i == ARRAY_SIZE(elements), "Got unexpected index %d.\n", i);

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        success = pRtlDeleteElementGenericTable(&table, &value);
        ok(success, "RtlDeleteElementGenericTable failed.\n");
    }
}

static void test_RtlGetElementGenericTable(void)
{
    static const int elements[] = {9, 1, 5, 4, 15, 11, 2, 3, 8, 6, 0, 10, 13, 14, 7, 12};
    RTL_SPLAY_LINKS *old_table_root;
    BOOLEAN success, new_element;
    RTL_GENERIC_TABLE table;
    int i, value, *ret;

    if (!pRtlGetElementGenericTable)
    {
        win_skip("RtlGetElementGenericTable is unavailable.\n");
        return;
    }

    pRtlInitializeGenericTable(&table, generic_compare_proc, generic_allocate_proc, generic_free_proc, NULL);

    ret = pRtlGetElementGenericTable(&table, 0);
    ok(!ret, "Got unexpected pointer.\n");

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
        ok(ret && *ret == value, "Got unexpected pointer.\n");
        ok(new_element, "Expected new element.\n");
    }

    /* Test that RtlGetElementGenericTable() changes WhichOrderedElement and OrderedPointer, but not TableRoot */
    old_table_root = table.TableRoot;
    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        ret = pRtlGetElementGenericTable(&table, i);
        ok(ret && *ret == elements[i], "Got unexpected pointer.\n");
        ok(table.WhichOrderedElement == i + 1, "Got unexpected WhichOrderedElement %lu.\n",
           table.WhichOrderedElement);
        ok(table.OrderedPointer == get_list_entry_from_data(ret), "Got unexpected OrderedPointer.\n");
        ok(table.TableRoot == old_table_root, "Got unexpected TableRoot.\n");
    }

    /* RtlInsertElementGenericTable() shouldn't touch WhichOrderedElement */
    value = 20;
    ret = pRtlInsertElementGenericTable(&table, &value, sizeof(value), &new_element);
    ok(ret && *ret == 20, "Got unexpected pointer.\n");
    ok(new_element, "Expected new element.\n");
    ok(table.WhichOrderedElement == ARRAY_SIZE(elements), "Got unexpected WhichOrderedElement %lu.\n",
       table.WhichOrderedElement);

    /* RtlGetElementGenericTable() updates WhichOrderedElement. WhichOrderedElement points to the
     * result element but its index starts from 1 instead of 0 */
    ret = pRtlGetElementGenericTable(&table, 1);
    ok(ret && *ret == elements[1], "Got unexpected pointer.\n");
    ok(table.WhichOrderedElement == 2, "Got unexpected WhichOrderedElement %lu.\n",
       table.WhichOrderedElement);
    ok(table.OrderedPointer == get_list_entry_from_data(ret), "Got unexpected OrderedPointer.\n");

    /* RtlDeleteElementGenericTable() should reset WhichOrderedElement and OrderedPointer */
    value = 20;
    success = pRtlDeleteElementGenericTable(&table, &value);
    ok(success, "RtlDeleteElementGenericTable failed.\n");
    ok(table.WhichOrderedElement == 0, "Got unexpected WhichOrderedElement %lu.\n", table.WhichOrderedElement);
    ok(table.OrderedPointer == &table.InsertOrderList, "Got unexpected OrderedPointer.\n");

    /* Out of order RtlGetElementGenericTable() calls */
    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        ret = pRtlGetElementGenericTable(&table, elements[i]);
        ok(ret && *ret == elements[elements[i]], "Expected %d got %d at %d.\n",
           elements[elements[i]], *ret,  elements[i]);
        ok(table.WhichOrderedElement == elements[i] + 1, "Got unexpected WhichOrderedElement %lu.\n",
           table.WhichOrderedElement);
        ok(table.OrderedPointer == get_list_entry_from_data(ret), "Got unexpected OrderedPointer.\n");
    }

    /* Out of range RtlGetElementGenericTable() call */
    ret = pRtlGetElementGenericTable(&table, ARRAY_SIZE(elements));
    ok(!ret, "Got unexpected pointer.\n");

    for (i = 0; i < ARRAY_SIZE(elements); i++)
    {
        value = elements[i];
        success = pRtlDeleteElementGenericTable(&table, &value);
        ok(success, "RtlDeleteElementGenericTable failed.\n");
    }
}

static void test_RtlCreateServiceSid(void)
{
    UNICODE_STRING service_name;
    SID* service_sid;
    ULONG service_sid_length = 0;
    LPWSTR string_sid;

    if (!pRtlCreateServiceSid)
    {
        win_skip( "RtlCreateServiceSid is not available.\n" );
        return;
    }

    RtlInitUnicodeString( &service_name, L"TestService" );
    ok( pRtlCreateServiceSid(NULL, NULL, &service_sid_length) == STATUS_INVALID_PARAMETER, "NULL pServiceName is invalid.\n" );
    ok( pRtlCreateServiceSid(&service_name, NULL, NULL) == STATUS_INVALID_PARAMETER, "NULL pServiceSidLength is invalid.\n" );
    ok( pRtlCreateServiceSid(&service_name, NULL, &service_sid_length) == STATUS_BUFFER_TOO_SMALL, "SID buffer must be big enough.\n" );
    ok( service_sid_length != 0, "The length should be written if the buffer is too small" );
    service_sid = malloc( service_sid_length );
    ok( pRtlCreateServiceSid(&service_name, service_sid, &service_sid_length) == STATUS_SUCCESS, "The length from the a previous call should be enough.\n" );
    ConvertSidToStringSidW(service_sid, &string_sid);
    ok( wcscmp(string_sid, L"S-1-5-80-3892056402-659729507-4115993473-1921682939-1565901394") == 0, "TestService SID is wrong");
    free(service_sid);
}

static void test_RtlDeriveCapabilitySidsFromName(void)
{
    static const SID_IDENTIFIER_AUTHORITY app_authority = { SECURITY_APP_PACKAGE_AUTHORITY };
    static SID_IDENTIFIER_AUTHORITY nt_authority = { SECURITY_NT_AUTHORITY };
    struct
    {
        const WCHAR *name;
        DWORD hash[8];
    }
    tests[] =
    {
        { NULL,    { 0x42c4b0e3, 0x141cfc98, 0xc8f4fb9a, 0x24b96f99, 0xe441ae27, 0x4c939b64, 0x1b9995a4, 0x55b85278, }},
        { L"__AB", { 0xddd798eb, 0x367bd9d0, 0x1c9e610a, 0x0c43dc7e, 0xe91d8625, 0x395e7cf8, 0xe6e7c3d2, 0x2661e620 }},
        { L"__ab", { 0xddd798eb, 0x367bd9d0, 0x1c9e610a, 0x0c43dc7e, 0xe91d8625, 0x395e7cf8, 0xe6e7c3d2, 0x2661e620 }},
        { L"0123456789012345678901234567890123456789",
                   { 0x3c45e3e6, 0xa598e751, 0x2eb11e4c, 0x04e073fd, 0xb7c331a3, 0x07b1214d, 0xd8dee260, 0xa0966ecf }},
    };
    UNICODE_STRING cap_name;
    SID *group_sid, *sid;
    unsigned int i, size;
    NTSTATUS status;

    if (!pRtlDeriveCapabilitySidsFromName)
    {
        win_skip( "RtlDeriveCapabilitySidsFromName is not available.\n" );
        return;
    }

    size = RtlLengthRequiredSid( 10 );
    sid = malloc( size );
    group_sid = malloc( size );

    for (i = 0; i < ARRAY_SIZE(tests); ++i)
    {
        winetest_push_context( "%s", debugstr_w(tests[i].name) );
        memset( sid, 0, size );
        memset( group_sid, 0, size );
        RtlInitUnicodeString( &cap_name, tests[i].name );
        status = pRtlDeriveCapabilitySidsFromName( &cap_name, group_sid, sid );
        ok( !status, "got %#lx.\n", status );

        ok( sid->Revision == SID_REVISION, "got %u.\n", sid->Revision );
        ok( !memcmp( &sid->IdentifierAuthority, &app_authority, sizeof(app_authority) ), "mismatch.\n" );
        ok( sid->SubAuthorityCount == 10, "got %u.\n", sid->SubAuthorityCount );
        ok ( sid->SubAuthority[0] == SECURITY_BATCH_RID, "got %lu.\n", sid->SubAuthority[0] );
        ok ( sid->SubAuthority[1] == SECURITY_CAPABILITY_APP_RID, "got %lu.\n", sid->SubAuthority[1] );
        ok( !memcmp( sid->SubAuthority + 2, tests[i].hash, sizeof(tests[i].hash) ), "mismatch.\n" );

        ok( group_sid->Revision == SID_REVISION, "got %u.\n", group_sid->Revision );
        ok( !memcmp( &group_sid->IdentifierAuthority, &nt_authority, sizeof(nt_authority) ), "mismatch.\n" );
        ok( group_sid->SubAuthorityCount == 9, "got %u.\n", group_sid->SubAuthorityCount );
        ok ( group_sid->SubAuthority[0] == SECURITY_BUILTIN_DOMAIN_RID, "got %lu.\n", group_sid->SubAuthority[0] );
        ok( !memcmp( group_sid->SubAuthority + 1, tests[i].hash, sizeof(tests[i].hash) ), "mismatch.\n" );
        winetest_pop_context();
    }

    free( sid );
    free( group_sid );
}

static void test_RtlCapabilityCheck(void)
{
    HANDLE process_token, impersonation_token;
    UNICODE_STRING cap_name;
    BOOLEAN result;
    NTSTATUS status;
    BOOL ret;

    if (!pRtlCapabilityCheck)
    {
        win_skip( "RtlCapabilityCheck is not available.\n" );
        return;
    }

    RtlInitUnicodeString( &cap_name, L"packageContents" );

    result = 0xcc;
    SetLastError( 0x13579bdf );
    status = pRtlCapabilityCheck( NULL, &cap_name, &result );
    ok( status == STATUS_SUCCESS, "got %#lx.\n", status );
    ok( result == TRUE, "got %u.\n", result );
    ok( GetLastError() == 0x13579bdf, "got error %lu.\n", GetLastError() );

    ret = OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token );
    ok( ret, "OpenProcessToken failed, error %lu.\n", GetLastError() );

    result = 0xcc;
    SetLastError( 0x13579bdf );
    status = pRtlCapabilityCheck( process_token, &cap_name, &result );
    ok( status == STATUS_NO_IMPERSONATION_TOKEN, "got %#lx.\n", status );
    ok( result == FALSE, "got %u.\n", result );
    ok( GetLastError() == 0x13579bdf, "got error %lu.\n", GetLastError() );

    ret = DuplicateToken( process_token, SecurityImpersonation, &impersonation_token );
    ok( ret, "DuplicateToken failed, error %lu.\n", GetLastError() );
    result = 0xcc;
    SetLastError( 0x13579bdf );
    status = pRtlCapabilityCheck( impersonation_token, &cap_name, &result );
    ok( status == STATUS_SUCCESS, "got %#lx.\n", status );
    ok( result == TRUE, "got %u.\n", result );
    ok( GetLastError() == 0x13579bdf, "got error %lu.\n", GetLastError() );

    result = 0xcc;
    status = pRtlCapabilityCheck( (HANDLE)0xdead, &cap_name, &result );
    ok( status == STATUS_INVALID_HANDLE, "got %#lx.\n", status );
    ok( result == FALSE, "got %u.\n", result );

    result = 0xcc;
    status = pRtlCapabilityCheck( process_token, NULL, &result );
    ok( status == STATUS_INVALID_PARAMETER, "got %#lx.\n", status );
    ok( result == 0xcc, "got %u.\n", result );

    CloseHandle( impersonation_token );
    CloseHandle( process_token );
}

static void test_RtlCheckTokenCapability(void)
{
    static const WCHAR *names[] = { L"muma", L"packageContents" };
    struct { TOKEN_USER user; BYTE sid[SECURITY_MAX_SID_SIZE]; } user;
    BYTE cap_group[SECURITY_MAX_SID_SIZE], cap_sid[SECURITY_MAX_SID_SIZE];
    SID_IDENTIFIER_AUTHORITY world_authority = { SECURITY_WORLD_SID_AUTHORITY };
    HANDLE process_token, token, restricted, no_query, reopened;
    TOKEN_STATISTICS before, after;
    SID_AND_ATTRIBUTES restriction;
    UNICODE_STRING name;
    BOOLEAN result;
    NTSTATUS status;
    PSID world_sid;
    DWORD size;
    BOOL ret;
    unsigned int i, j;

    if (!pRtlCheckTokenCapability || !pRtlDeriveCapabilitySidsFromName)
    {
        win_skip( "Token capability functions are unavailable.\n" );
        return;
    }
    ret = OpenProcessToken( GetCurrentProcess(), TOKEN_QUERY | TOKEN_DUPLICATE, &process_token );
    ok( ret, "OpenProcessToken failed, error %lu.\n", GetLastError() );
    if (!ret) return;
    ret = DuplicateTokenEx( process_token, TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                           NULL, SecurityImpersonation, TokenImpersonation, &token );
    ok( ret, "DuplicateTokenEx failed, error %lu.\n", GetLastError() );
    if (!ret) { CloseHandle( process_token ); return; }
    ret = GetTokenInformation( token, TokenUser, &user, sizeof(user), &size );
    ok( ret, "TokenUser failed, error %lu.\n", GetLastError() );
    if (!ret) goto done;
    ret = AllocateAndInitializeSid( &world_authority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &world_sid );
    ok( ret, "AllocateAndInitializeSid failed.\n" );
    if (!ret) goto done;

    ret = GetTokenInformation( token, TokenStatistics, &before, sizeof(before), &size );
    ok( ret, "TokenStatistics failed.\n" );
    for (i = 0; i < ARRAY_SIZE(names); ++i)
    {
        RtlInitUnicodeString( &name, names[i] );
        status = pRtlDeriveCapabilitySidsFromName( &name, cap_group, cap_sid );
        ok( !status, "derive %s returned %#lx.\n", wine_dbgstr_w(names[i]), status );
        result = 0xcc;
        SetLastError( 0x13579bdf );
        status = pRtlCheckTokenCapability( token, cap_sid, &result );
        ok( status == STATUS_SUCCESS, "%s returned %#lx.\n", wine_dbgstr_w(names[i]), status );
        ok( result == TRUE, "%s returned %u.\n", wine_dbgstr_w(names[i]), result );
        ok( GetLastError() == 0x13579bdf, "got error %lu.\n", GetLastError() );
        result = 0xcc;
        status = pRtlCheckTokenCapability( NULL, cap_sid, &result );
        ok( !status && result == TRUE, "effective token returned %#lx, %u.\n", status, result );
    }
    ret = GetTokenInformation( token, TokenStatistics, &after, sizeof(after), &size );
    ok( ret, "TokenStatistics failed.\n" );
    ok( before.GroupCount == after.GroupCount && before.ModifiedId.LowPart == after.ModifiedId.LowPart &&
        before.ModifiedId.HighPart == after.ModifiedId.HighPart, "capability check mutated token state.\n" );

    result = 0xcc;
    status = pRtlCheckTokenCapability( process_token, cap_sid, &result );
    ok( status == STATUS_NO_IMPERSONATION_TOKEN && result == FALSE, "primary token returned %#lx, %u.\n", status, result );
    result = 0xcc;
    status = pRtlCheckTokenCapability( (HANDLE)0xdead, cap_sid, &result );
    ok( status == STATUS_INVALID_HANDLE && result == FALSE, "invalid handle returned %#lx, %u.\n", status, result );
    result = 0xcc;
    status = pRtlCheckTokenCapability( token, world_sid, &result );
    ok( status == STATUS_INVALID_PARAMETER && result == FALSE, "non-capability SID returned %#lx, %u.\n", status, result );

    ret = DuplicateHandle( GetCurrentProcess(), token, GetCurrentProcess(), &no_query, TOKEN_DUPLICATE, FALSE, 0 );
    ok( ret, "DuplicateHandle failed.\n" );
    if (ret)
    {
        result = 0xcc;
        status = pRtlCheckTokenCapability( no_query, cap_sid, &result );
        ok( status == STATUS_ACCESS_DENIED && result == FALSE, "unqueryable token returned %#lx, %u.\n", status, result );
        CloseHandle( no_query );
    }

    /* The restricting set must authorize the same descriptor separately. */
    for (j = 0; j < 3; ++j)
    {
        restriction.Sid = j == 0 ? world_sid : j == 1 ? user.user.User.Sid : (PSID)cap_sid;
        restriction.Attributes = 0;
        ret = CreateRestrictedToken( token, 0, 0, NULL, 0, NULL, 1, &restriction, &restricted );
        ok( ret, "CreateRestrictedToken %u failed, error %lu.\n", j, GetLastError() );
        if (!ret) continue;
        result = 0xcc;
        status = pRtlCheckTokenCapability( restricted, cap_sid, &result );
        ok( status == STATUS_SUCCESS && result == (j != 0),
            "restricted %u returned %#lx, %u.\n", j, status, result );
        ret = SetThreadToken( NULL, restricted );
        ok( ret, "SetThreadToken failed, error %lu.\n", GetLastError() );
        if (ret)
        {
            status = NtOpenThreadToken( GetCurrentThread(), TOKEN_QUERY, TRUE, &reopened );
            ok( status == STATUS_SUCCESS, "OpenAsSelf restricted %u returned %#lx.\n", j, status );
            if (!status) CloseHandle( reopened );
            result = 0xcc;
            status = pRtlCheckTokenCapability( NULL, cap_sid, &result );
            ok( status == STATUS_SUCCESS && result == (j != 0),
                "effective restricted %u returned %#lx, %u.\n", j, status, result );
            ret = SetThreadToken( NULL, NULL );
            ok( ret, "reset thread token failed, error %lu.\n", GetLastError() );
        }
        CloseHandle( restricted );
    }
    FreeSid( world_sid );
done:
    CloseHandle( token );
    CloseHandle( process_token );
}

static ULONG_PTR rotate_bits_right( ULONG_PTR v, ULONG count )
{
    static const unsigned int bits = sizeof(v) * 8;

    count %= bits;
    return (v >> count) | (v << ((bits - count) % bits));
}

static ULONG_PTR rotate_bits_left( ULONG_PTR v, ULONG count )
{
    static const unsigned int bits = sizeof(v) * 8;

    count %= bits;
    return (v << count) | (v >> ((bits - count) % bits));
}

static ULONG process_cookie;

static void *encode_pointer( void *ptr )
{
    DWORD_PTR ptrval = (DWORD_PTR)ptr;
    return (void *)rotate_bits_right( ptrval ^ process_cookie, process_cookie );
}

static void *decode_pointer( void *ptr )
{
    DWORD_PTR ptrval = (DWORD_PTR)ptr;
    return (void *)(rotate_bits_left( ptrval, process_cookie ) ^ process_cookie );
}

static void test_pointer_encoding(void)
{
    void *v, *expected;

    if (NtQueryInformationProcess( GetCurrentProcess(), ProcessCookie, &process_cookie, sizeof(process_cookie), NULL ))
    {
        win_skip( "Could not get process cookie, skipping tests.\n" );
        return;
    }
    ok( process_cookie, "got 0.\n" );

    v = RtlEncodePointer( NULL );
    expected = encode_pointer( NULL );
    ok( v == expected, "got %p, expected %p.\n", v, expected );
    v = RtlDecodePointer( v );
    expected = decode_pointer( expected );
    ok( v == expected, "got %p, expected %p.\n", v, expected );

    v = RtlEncodePointer( (void *)(ULONG_PTR)1 );
    expected = encode_pointer( (void *)(ULONG_PTR)1 );
    ok( v == expected, "got %p, expected %p.\n", v, expected );
    v = RtlDecodePointer( v );
    expected = decode_pointer( expected );
    ok( v == expected, "got %p, expected %p.\n", v, expected );

    v = RtlEncodePointer( (void *)(ULONG_PTR)0xdeadbeeffeedcafe );
    expected = encode_pointer( (void *)(ULONG_PTR)0xdeadbeeffeedcafe );
    ok( v == expected, "got %p, expected %p.\n", v, expected );
    v = RtlDecodePointer( v );
    expected = decode_pointer( expected );
    ok( v == expected, "got %p, expected %p.\n", v, expected );
}

static void test_process_protection(void)
{
    static const UCHAR valid[] =
    {
        0x00, 0x08, 0x12, 0x21, 0x31, 0x41, 0x51, 0x52, 0x61, 0x62, 0x72, 0x81
    };
    static const USHORT access_rows[] =
    {
        0x003, 0x003, 0x007, 0x00b, 0x813, 0x823,
        0x87b, 0x8ff, 0x97b, 0xbff, 0xfff, 0x003
    };
    unsigned int source, target, value;
    BOOL expected;

    if (!pRtlTestProtectedAccess || !pRtlValidProcessProtection)
    {
        win_skip("process protection helpers are unavailable.\n");
        return;
    }

    for (value = 0; value <= 0xff; ++value)
    {
        expected = FALSE;
        for (source = 0; source < ARRAY_SIZE(valid); ++source)
            if (value == valid[source]) expected = TRUE;
        ok(pRtlValidProcessProtection(value) == expected,
           "validity for %#x was unexpected.\n", value);
    }

    for (source = 0; source < ARRAY_SIZE(valid); ++source)
        for (target = 0; target < ARRAY_SIZE(valid); ++target)
        {
            expected = !!(access_rows[source] & (1u << target));
            ok(pRtlTestProtectedAccess(valid[source], valid[target]) == expected,
               "access from %#x to %#x was unexpected.\n", valid[source], valid[target]);
        }
}

START_TEST(rtl)
{
    InitFunctionPtrs();

    test_RtlQueryProcessDebugInformation();
    test_RtlCompareMemory();
    test_RtlCompareMemoryUlong();
    test_RtlMoveMemory();
    test_RtlFillMemory();
    test_RtlFillMemoryUlong();
    test_RtlZeroMemory();
    test_RtlByteSwap();
    test_RtlUniform();
    test_RtlRandom();
    test_RtlAreAllAccessesGranted();
    test_RtlAreAnyAccessesGranted();
    test_RtlAreLongPathsEnabled();
    test_process_protection();
    test_RtlComputeCrc32();
    test_RtlFlushHeaps();
    test_HandleTables();
    test_RtlAllocateAndInitializeSid();
    test_RtlDeleteTimer();
    test_RtlThreadErrorMode();
    test_LdrProcessRelocationBlock();
    test_RtlIpv4AddressToString();
    test_RtlIpv4AddressToStringEx();
    test_RtlIpv4StringToAddress();
    test_RtlIpv4StringToAddressEx();
    test_RtlIpv6AddressToString();
    test_RtlIpv6AddressToStringEx();
    test_RtlIpv6StringToAddress();
    test_RtlIpv6StringToAddressEx();
    test_LdrAddRefDll();
    test_LdrLockLoaderLock();
    test_RtlCompressBuffer();
    test_RtlGetCompressionWorkSpaceSize();
    test_RtlDecompressBuffer();
    test_RtlIsCriticalSectionLocked();
    test_RtlInitializeCriticalSectionEx();
    test_RtlLeaveCriticalSection();
    test_LdrEnumerateLoadedModules();
    test_RtlMakeSelfRelativeSD();
    test_LdrRegisterDllNotification();
    test_DbgPrint();
    test_RtlDestroyHeap();
    test_RtlCreateHeap();
    test_RtlFirstFreeAce();
    test_RtlGetAcesBufferSize();
    test_RtlInitializeSid();
    test_RtlCopySid();
    test_RtlSidHash();
    test_RtlValidSecurityDescriptor();
    test_RtlValidRelativeSecurityDescriptor();
    test_RtlValidAcl();
    test_RtlCopySecurityDescriptor();
    test_RtlSetSecurityObject();
    test_RtlCreateAndSetSD();
    test_RtlCreateUserSecurityObject();
    test_RtlFindExportedRoutineByName();
    test_RtlGetDeviceFamilyInfoEnum();
    test_RtlConvertDeviceFamilyInfoToString();
    test_rb_tree();
    test_user_procs();
    test_RtlSubtreePredecessor();
    test_RtlSubtreeSuccessor();
    test_RtlRealPredecessor();
    test_RtlRealSuccessor();
    test_RtlSplay();
    test_RtlDeleteNoSplay();
    test_RtlDelete();
    test_RtlEnumerateGenericTableAvl();
    test_RtlInitializeGenericTable();
    test_RtlNumberGenericTableElements();
    test_RtlIsGenericTableEmpty();
    test_RtlInsertElementGenericTable();
    test_RtlDeleteElementGenericTable();
    test_RtlLookupElementGenericTable();
    test_RtlEnumerateGenericTableWithoutSplaying();
    test_RtlEnumerateGenericTable();
    test_RtlGetElementGenericTable();
    test_RtlCreateServiceSid();
    test_RtlDeriveCapabilitySidsFromName();
    test_RtlCapabilityCheck();
    test_RtlCheckTokenCapability();
    test_pointer_encoding();
}
