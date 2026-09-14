153 stdcall -noname RoGetRegistrationStoreContext(long ptr long ptr ptr)
164 stdcall -noname RpcMarshalRestrictedErrorFromTlsToExtent(ptr ptr)
165 stdcall -noname RpcMarshalRestrictedErrorFromTls(ptr ptr)
166 stdcall -noname RpcUnmarshalRestrictedErrorToTls(ptr ptr)
176 stdcall -noname OriginateOrTransformError(long)
177 stdcall -noname SetChainRestrictedErrors()
178 stdcall -noname ClearChainRestrictedErrors()

1 extern ObjectStublessClient3 rpcrt4.__wine_ObjectStublessClient3
@ extern ObjectStublessClient4 rpcrt4.__wine_ObjectStublessClient4
@ extern ObjectStublessClient5 rpcrt4.__wine_ObjectStublessClient5
@ extern ObjectStublessClient6 rpcrt4.__wine_ObjectStublessClient6
@ extern ObjectStublessClient7 rpcrt4.__wine_ObjectStublessClient7
@ extern ObjectStublessClient8 rpcrt4.__wine_ObjectStublessClient8
@ extern ObjectStublessClient9 rpcrt4.__wine_ObjectStublessClient9
@ extern ObjectStublessClient10 rpcrt4.__wine_ObjectStublessClient10
@ extern ObjectStublessClient11 rpcrt4.__wine_ObjectStublessClient11
@ extern ObjectStublessClient12 rpcrt4.__wine_ObjectStublessClient12
@ extern ObjectStublessClient13 rpcrt4.__wine_ObjectStublessClient13
@ extern ObjectStublessClient14 rpcrt4.__wine_ObjectStublessClient14
@ extern ObjectStublessClient15 rpcrt4.__wine_ObjectStublessClient15
@ extern ObjectStublessClient16 rpcrt4.__wine_ObjectStublessClient16
@ extern ObjectStublessClient17 rpcrt4.__wine_ObjectStublessClient17
@ extern ObjectStublessClient18 rpcrt4.__wine_ObjectStublessClient18
@ extern ObjectStublessClient19 rpcrt4.__wine_ObjectStublessClient19
@ extern ObjectStublessClient20 rpcrt4.__wine_ObjectStublessClient20
@ extern ObjectStublessClient21 rpcrt4.__wine_ObjectStublessClient21
@ extern ObjectStublessClient22 rpcrt4.__wine_ObjectStublessClient22
@ extern ObjectStublessClient23 rpcrt4.__wine_ObjectStublessClient23
@ extern ObjectStublessClient24 rpcrt4.__wine_ObjectStublessClient24
@ extern ObjectStublessClient25 rpcrt4.__wine_ObjectStublessClient25
@ extern ObjectStublessClient26 rpcrt4.__wine_ObjectStublessClient26
@ extern ObjectStublessClient27 rpcrt4.__wine_ObjectStublessClient27
@ extern ObjectStublessClient28 rpcrt4.__wine_ObjectStublessClient28
@ extern ObjectStublessClient29 rpcrt4.__wine_ObjectStublessClient29
@ extern ObjectStublessClient30 rpcrt4.__wine_ObjectStublessClient30
@ extern ObjectStublessClient31 rpcrt4.__wine_ObjectStublessClient31
@ extern ObjectStublessClient32 rpcrt4.__wine_ObjectStublessClient32
@ extern NdrProxyForwardingFunction3 rpcrt4.__wine_NdrProxyForwardingFunction3
@ extern NdrProxyForwardingFunction4 rpcrt4.__wine_NdrProxyForwardingFunction4
@ extern NdrProxyForwardingFunction5 rpcrt4.__wine_NdrProxyForwardingFunction5
@ extern NdrProxyForwardingFunction6 rpcrt4.__wine_NdrProxyForwardingFunction6
@ extern NdrProxyForwardingFunction7 rpcrt4.__wine_NdrProxyForwardingFunction7
@ extern NdrProxyForwardingFunction8 rpcrt4.__wine_NdrProxyForwardingFunction8
@ extern NdrProxyForwardingFunction9 rpcrt4.__wine_NdrProxyForwardingFunction9
@ extern NdrProxyForwardingFunction10 rpcrt4.__wine_NdrProxyForwardingFunction10
@ extern NdrProxyForwardingFunction11 rpcrt4.__wine_NdrProxyForwardingFunction11
@ extern NdrProxyForwardingFunction12 rpcrt4.__wine_NdrProxyForwardingFunction12
@ extern NdrProxyForwardingFunction13 rpcrt4.__wine_NdrProxyForwardingFunction13
@ extern NdrProxyForwardingFunction14 rpcrt4.__wine_NdrProxyForwardingFunction14
@ extern NdrProxyForwardingFunction15 rpcrt4.__wine_NdrProxyForwardingFunction15
@ extern NdrProxyForwardingFunction16 rpcrt4.__wine_NdrProxyForwardingFunction16
@ extern NdrProxyForwardingFunction17 rpcrt4.__wine_NdrProxyForwardingFunction17
@ extern NdrProxyForwardingFunction18 rpcrt4.__wine_NdrProxyForwardingFunction18
@ extern NdrProxyForwardingFunction19 rpcrt4.__wine_NdrProxyForwardingFunction19
@ extern NdrProxyForwardingFunction20 rpcrt4.__wine_NdrProxyForwardingFunction20
@ extern NdrProxyForwardingFunction21 rpcrt4.__wine_NdrProxyForwardingFunction21
@ extern NdrProxyForwardingFunction22 rpcrt4.__wine_NdrProxyForwardingFunction22
@ extern NdrProxyForwardingFunction23 rpcrt4.__wine_NdrProxyForwardingFunction23
@ extern NdrProxyForwardingFunction24 rpcrt4.__wine_NdrProxyForwardingFunction24
@ extern NdrProxyForwardingFunction25 rpcrt4.__wine_NdrProxyForwardingFunction25
@ extern NdrProxyForwardingFunction26 rpcrt4.__wine_NdrProxyForwardingFunction26
@ extern NdrProxyForwardingFunction27 rpcrt4.__wine_NdrProxyForwardingFunction27
@ extern NdrProxyForwardingFunction28 rpcrt4.__wine_NdrProxyForwardingFunction28
@ extern NdrProxyForwardingFunction29 rpcrt4.__wine_NdrProxyForwardingFunction29
@ extern NdrProxyForwardingFunction30 rpcrt4.__wine_NdrProxyForwardingFunction30
@ extern NdrProxyForwardingFunction31 rpcrt4.__wine_NdrProxyForwardingFunction31
@ extern NdrProxyForwardingFunction32 rpcrt4.__wine_NdrProxyForwardingFunction32
@ stub NdrOleInitializeExtension
@ stdcall RoFailFastWithErrorContextInternal2(long long ptr)
@ stub RoFailFastWithErrorContextInternal
@ stub UpdateProcessTracing
@ stdcall CLIPFORMAT_UserFree(ptr ptr)
@ stdcall CLIPFORMAT_UserMarshal(ptr ptr ptr)
@ stdcall CLIPFORMAT_UserSize(ptr long ptr)
@ stdcall CLIPFORMAT_UserUnmarshal(ptr ptr ptr)
@ stub CLSIDFromOle1Class
@ stdcall CLSIDFromProgID(wstr ptr)
@ stdcall CLSIDFromProgIDEx(wstr ptr)
@ stdcall CLSIDFromString(wstr ptr)
@ stdcall CleanupOleStateInAllTls()
@ stdcall CleanupTlsOleState(ptr)
@ stdcall ClearCleanupFlag(long)
@ stdcall CoAddRefServerProcess()
@ stub CoAllowUnmarshalerCLSID
@ stub CoCancelCall
@ stdcall CoCopyProxy(ptr ptr)
@ stdcall CoCreateErrorInfo(ptr) CreateErrorInfo
@ stdcall CoCreateFreeThreadedMarshaler(ptr ptr)
@ stdcall CoCreateGuid(ptr)
@ stdcall CoCreateInstance(ptr ptr long ptr ptr)
@ stdcall CoCreateInstanceEx(ptr ptr long ptr long ptr)
@ stdcall CoCreateInstanceFromApp(ptr ptr long ptr long ptr)
@ stub CoCreateObjectInContext
@ stub CoDeactivateObject
@ stdcall CoDecodeProxy(long int64 ptr)
@ stdcall CoDecrementMTAUsage(ptr)
@ stdcall CoDisableCallCancellation(ptr)
@ stub CoDisconnectContext
@ stdcall CoDisconnectObject(ptr long)
@ stdcall CoEnableCallCancellation(ptr)
@ stdcall CoFileTimeNow(ptr)
@ stdcall CoFreeUnusedLibraries()
@ stdcall CoFreeUnusedLibrariesEx(long long)
@ stdcall CoGetActivationState(int128 long ptr)
@ stub CoGetApartmentID
@ stdcall CoGetApartmentType(ptr ptr)
@ stdcall CoGetCallContext(ptr ptr)
@ stdcall CoGetCallState(long ptr)
@ stdcall CoGetCallerTID(ptr)
@ stub CoGetCancelObject
@ stdcall CoGetClassObject(ptr long ptr ptr ptr)
@ stub CoGetClassVersion
@ stdcall CoGetContextToken(ptr)
@ stdcall CoGetCurrentLogicalThreadId(ptr)
@ stdcall CoGetCurrentProcess()
@ stdcall CoGetDefaultContext(long ptr ptr)
@ stdcall CoGetErrorInfo(long ptr) GetErrorInfo
@ stdcall CoGetInstanceFromFile(ptr ptr ptr long long wstr long ptr)
@ stdcall CoGetInstanceFromIStorage(ptr ptr ptr long ptr long ptr)
@ stdcall CoGetInterfaceAndReleaseStream(ptr ptr ptr)
@ stdcall CoGetMalloc(long ptr)
@ stdcall CoGetMarshalSizeMax(ptr ptr ptr long ptr long)
@ stub CoGetModuleType
@ stdcall CoGetObjectContext(ptr ptr)
@ stdcall CoGetPSClsid(ptr ptr)
@ stub CoGetProcessIdentifier
@ stdcall CoRegisterForApartmentShutdown(ptr ptr ptr) RoRegisterForApartmentShutdown
@ stub CoGetStdMarshalEx
@ stdcall CoGetApartmentIdentifier(ptr)
@ stdcall CoGetTreatAsClass(ptr ptr)
@ stdcall CoImpersonateClient()
@ stdcall CoIncrementMTAUsage(ptr)
@ stdcall CoInitializeEx(ptr long)
@ stdcall CoInitializeSecurity(ptr long ptr ptr long long ptr long ptr)
@ stdcall CoInitializeWOW(long long)
@ stub CoInvalidateRemoteMachineBindings
@ stdcall CoIsHandlerConnected(ptr)
@ stdcall CoIsOle1Class(ptr)
@ stdcall CoLockObjectExternal(ptr long long)
@ stdcall CoMarshalHresult(ptr long)
@ stdcall CoMarshalInterThreadInterfaceInStream(ptr ptr ptr)
@ stdcall CoMarshalInterface(ptr ptr ptr long ptr long)
@ stub CoPopServiceDomain
@ stub CoPushServiceDomain
@ stub CoQueryAuthenticationServices
@ stdcall CoQueryClientBlanket(ptr ptr ptr ptr ptr ptr ptr)
@ stdcall CoQueryProxyBlanket(ptr ptr ptr ptr ptr ptr ptr ptr)
@ stub CoReactivateObject
@ stdcall CoRegisterActivationFilter(ptr)
@ stdcall CoRegisterChannelHook(ptr ptr)
@ stdcall CoRegisterClassObject(ptr ptr long long ptr)
@ stdcall CoRegisterInitializeSpy(ptr ptr)
@ stdcall CoRegisterMallocSpy(ptr)
@ stdcall CoRegisterMessageFilter(ptr ptr)
@ stdcall CoRegisterPSClsid(ptr ptr)
@ stdcall CoRegisterSurrogate(ptr)
@ stdcall CoRegisterSurrogateEx(ptr ptr)
@ stdcall CoReleaseMarshalData(ptr)
@ stdcall CoReleaseServerProcess()
@ stdcall CoResumeClassObjects()
@ stub CoRetireServer
@ stdcall CoRevertToSelf()
@ stdcall CoRevokeClassObject(long)
@ stdcall CoRevokeInitializeSpy(int64)
@ stdcall CoRevokeMallocSpy()
@ stub CoSetCancelObject
@ stdcall CoSetErrorInfo(long ptr) SetErrorInfo
@ stdcall CoSetOutgoingCallState(ptr ptr)
@ stdcall CoSetProxyBlanket(ptr long long ptr long long ptr long)
@ stdcall CoSuspendClassObjects()
@ stdcall CoSwitchCallContext(ptr ptr)
@ stdcall CoTaskMemAlloc(long)
@ stdcall CoTaskMemFree(ptr)
@ stdcall CoTaskMemRealloc(ptr long)
@ stub CoTestCancel
@ stdcall CoTreatAsClass(ptr ptr)
@ stdcall CoUninitialize()
@ stub CoUnloadingWOW
@ stdcall CoUnmarshalHresult(ptr ptr)
@ stdcall CoUnmarshalInterface(ptr ptr ptr)
@ stub CoVrfCheckThreadState
@ stub CoVrfGetThreadState
@ stub CoVrfReleaseThreadState
@ stdcall CoWaitForMultipleHandles(long long long ptr ptr)
@ stub CoWaitForMultipleObjects
@ stdcall CreateErrorInfo(ptr)
@ stdcall CreateStreamOnHGlobal(ptr long ptr)
@ stub DcomChannelSetHResult
@ stdcall DllDebugObjectRPCHook(long ptr)
@ stdcall DllGetActivationFactory(ptr ptr)
@ stdcall -private DllGetClassObject(ptr ptr ptr)
@ stub EnableHookObject
@ stdcall FreePropVariantArray(long ptr)
@ stub FreePropVariantArrayWorker
@ stub GetCatalogHelper
@ stdcall GetErrorInfo(long ptr)
@ stub GetFuncDescs
@ stdcall GetHGlobalFromStream(ptr ptr)
@ stub GetHookInterface
@ stdcall GetRestrictedErrorInfo(ptr)
@ stdcall HACCEL_UserFree(ptr ptr)
@ stdcall HACCEL_UserMarshal(ptr ptr ptr)
@ stdcall HACCEL_UserSize(ptr long ptr)
@ stdcall HACCEL_UserUnmarshal(ptr ptr ptr)
@ stdcall HBITMAP_UserFree(ptr ptr)
@ stdcall HBITMAP_UserMarshal(ptr ptr ptr)
@ stdcall HBITMAP_UserSize(ptr long ptr)
@ stdcall HBITMAP_UserUnmarshal(ptr ptr ptr)
@ stdcall HBRUSH_UserFree(ptr ptr)
@ stdcall HBRUSH_UserMarshal(ptr ptr ptr)
@ stdcall HBRUSH_UserSize(ptr long ptr)
@ stdcall HBRUSH_UserUnmarshal(ptr ptr ptr)
@ stdcall HDC_UserFree(ptr ptr)
@ stdcall HDC_UserMarshal(ptr ptr ptr)
@ stdcall HDC_UserSize(ptr long ptr)
@ stdcall HDC_UserUnmarshal(ptr ptr ptr)
@ stdcall HGLOBAL_UserFree(ptr ptr)
@ stdcall HGLOBAL_UserMarshal(ptr ptr ptr)
@ stdcall HGLOBAL_UserSize(ptr long ptr)
@ stdcall HGLOBAL_UserUnmarshal(ptr ptr ptr)
@ stdcall HICON_UserFree(ptr ptr)
@ stdcall HICON_UserMarshal(ptr ptr ptr)
@ stdcall HICON_UserSize(ptr long ptr)
@ stdcall HICON_UserUnmarshal(ptr ptr ptr)
@ stdcall HMENU_UserFree(ptr ptr)
@ stdcall HMENU_UserMarshal(ptr ptr ptr)
@ stdcall HMENU_UserSize(ptr long ptr)
@ stdcall HMENU_UserUnmarshal(ptr ptr ptr)
@ stdcall HPALETTE_UserFree(ptr ptr)
@ stdcall HPALETTE_UserMarshal(ptr ptr ptr)
@ stdcall HPALETTE_UserSize(ptr long ptr)
@ stdcall HPALETTE_UserUnmarshal(ptr ptr ptr)
@ stdcall HSTRING_UserFree(ptr ptr)
@ stdcall -arch=win64 HSTRING_UserFree64(ptr ptr)
@ stdcall HSTRING_UserMarshal(ptr ptr ptr)
@ stdcall -arch=win64 HSTRING_UserMarshal64(ptr ptr ptr)
@ stdcall HSTRING_UserSize(ptr long ptr)
@ stdcall -arch=win64 HSTRING_UserSize64(ptr long ptr)
@ stdcall HSTRING_UserUnmarshal(ptr ptr ptr)
@ stdcall -arch=win64 HSTRING_UserUnmarshal64(ptr ptr ptr)
@ stdcall HWND_UserFree(ptr ptr)
@ stdcall HWND_UserMarshal(ptr ptr ptr)
@ stdcall HWND_UserSize(ptr long ptr)
@ stdcall HWND_UserUnmarshal(ptr ptr ptr)
@ stub HkOleRegisterObject
@ stdcall IIDFromString(wstr ptr)
@ stub InternalAppInvokeExceptionFilter
@ stub InternalCCFreeUnused
@ stub InternalCCGetClassInformationForDde
@ stub InternalCCGetClassInformationFromKey
@ stub InternalCCSetDdeServerWindow
@ stub InternalCMLSendReceive
@ stub InternalCallAsProxyExceptionFilter
@ stub InternalCallFrameExceptionFilter
@ stub InternalCallerIsAppContainer
@ stub InternalCanMakeOutCall
@ stub InternalCoIsSurrogateProcess
@ stub InternalCoRegisterDisconnectCallback
@ stub InternalCoRegisterSurrogatedObject
@ stdcall InternalCoStdMarshalObject(ptr long ptr ptr)
@ stub InternalCoUnregisterDisconnectCallback
@ stub InternalCompleteObjRef
@ stub InternalCreateCAggId
@ stub InternalCreateIdentityHandler
@ stub InternalDoATClassCreate
@ stub InternalFillLocalOXIDInfo
@ stub InternalFreeObjRef
@ stub InternalGetWindowPropInterface
@ stdcall InternalIrotEnumRunning(ptr)
@ stdcall InternalIrotGetObject(ptr ptr ptr)
@ stdcall InternalIrotGetTimeOfLastChange(ptr ptr)
@ stdcall InternalIrotIsRunning(ptr)
@ stdcall InternalIrotNoteChangeTime(long ptr)
@ stdcall InternalIrotRegister(ptr ptr ptr ptr long ptr ptr)
@ stdcall InternalIrotRevoke(long ptr ptr ptr)
@ stub InternalIsApartmentInitialized
@ stdcall InternalIsProcessInitialized()
@ stub InternalMarshalObjRef
@ stub InternalNotifyDDStartOrStop
@ stub InternalOleModalLoopBlockFn
@ stub InternalRegisterWindowPropInterface
@ stub InternalReleaseMarshalObjRef
@ stub InternalSTAInvoke
@ stub InternalServerExceptionFilter
@ stub InternalSetAptCallCtrlOnTlsIfRequired
@ stub InternalSetOleThunkWowPtr
@ stub InternalStubInvoke
@ stdcall InternalTlsAllocData(ptr)
@ stub InternalUnmarshalObjRef
@ stub IsErrorPropagationEnabled
@ stub NdrExtStubInitialize
@ stub NdrOleDllGetClassObject
@ stub NdrpFindInterface
@ stdcall ProgIDFromCLSID(ptr ptr)
@ stdcall PropVariantClear(ptr)
@ stdcall PropVariantCopy(ptr ptr)
@ stub ReleaseFuncDescs
@ stdcall RoActivateInstance(ptr ptr)
@ stub RoCaptureErrorContext
@ stub RoClearError
@ stdcall RoFailFastWithErrorContext(long)
@ stub RoFreeParameterizedTypeExtra
@ stub RoGetActivatableClassRegistration
@ stdcall RoGetActivationFactory(ptr ptr ptr)
@ stdcall RoGetAgileReference(long ptr ptr ptr)
@ stdcall RoGetApartmentIdentifier(ptr)
@ stdcall RoGetErrorReportingFlags(ptr)
@ stdcall RoGetMatchingRestrictedErrorInfo(long ptr)
@ stdcall RoGetParameterizedTypeInstanceIID(long ptr ptr ptr ptr)
@ stdcall CoGetStandardMarshal(ptr ptr long ptr long ptr)
@ stdcall RoInitialize(long)
@ stub RoInspectCapturedStackBackTrace
@ stub RoInspectThreadErrorInfo
@ stdcall RoOriginateError(long ptr)
@ stdcall RoOriginateErrorW(long long ptr)
@ stdcall RoOriginateLanguageException(long ptr ptr)
@ stub RoParameterizedTypeExtraGetTypeSignature
@ stdcall RoRegisterActivationFactories(ptr ptr long ptr)
@ stdcall RoRegisterForApartmentShutdown(ptr ptr ptr)
@ stub RoReportCapabilityCheckFailure
@ stub RoReportFailedDelegate
@ stdcall RoReportUnhandledError(ptr)
@ stub RoResolveRestrictedErrorInfoReference
@ stub RoRevokeActivationFactories
@ stdcall RoSetErrorReportingFlags(long)
@ stub RoTransformError
@ stub RoTransformErrorW
@ stdcall RoUninitialize()
@ stub RoUnregisterForApartmentShutdown
@ stdcall SetCleanupFlag(long)
@ stdcall SetErrorInfo(long ptr)
@ stdcall SetRestrictedErrorInfo(ptr)
@ stdcall StringFromCLSID(ptr ptr)
@ stdcall StringFromGUID2(ptr ptr long)
@ stdcall StringFromIID(ptr ptr) StringFromCLSID
@ stub UpdateDCOMSettings
@ stdcall WdtpInterfacePointer_UserFree(ptr)
@ stub -arch=win64 WdtpInterfacePointer_UserFree64
@ stdcall WdtpInterfacePointer_UserMarshal(ptr long ptr ptr ptr)
@ stub -arch=win64 WdtpInterfacePointer_UserMarshal64
@ stdcall WdtpInterfacePointer_UserSize(ptr long long ptr ptr)
@ stub -arch=win64 WdtpInterfacePointer_UserSize64
@ stdcall WdtpInterfacePointer_UserUnmarshal(ptr ptr ptr ptr)
@ stub -arch=win64 WdtpInterfacePointer_UserUnmarshal64
@ stdcall WindowsCompareStringOrdinal(ptr ptr ptr)
@ stdcall WindowsConcatString(ptr ptr ptr)
@ stdcall WindowsCreateString(wstr long ptr)
@ stdcall WindowsCreateStringReference(wstr long ptr ptr)
@ stdcall WindowsDeleteString(ptr)
@ stdcall WindowsDeleteStringBuffer(ptr)
@ stdcall WindowsDuplicateString(ptr ptr)
@ stdcall WindowsGetStringLen(ptr)
@ stdcall WindowsGetStringRawBuffer(ptr ptr)
@ stub WindowsInspectString
@ stdcall WindowsIsStringEmpty(ptr)
@ stdcall WindowsPreallocateStringBuffer(long ptr ptr)
@ stdcall WindowsPromoteStringBuffer(ptr ptr)
@ stub WindowsReplaceString
@ stdcall WindowsStringHasEmbeddedNull(ptr ptr)
@ stdcall WindowsSubstring(ptr long ptr)
@ stdcall WindowsSubstringWithSpecifiedLength(ptr long long ptr)
@ stdcall WindowsTrimStringEnd(ptr ptr ptr)
@ stdcall WindowsTrimStringStart(ptr ptr ptr)
@ stdcall CoGetSystemSecurityPermissions(long ptr)
@ stdcall RoGetServerActivatableClasses(ptr ptr ptr)
