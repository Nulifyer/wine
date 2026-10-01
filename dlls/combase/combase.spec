2 stub ObjectStublessClient3
3 stub ObjectStublessClient4
4 stub ObjectStublessClient5
5 stub ObjectStublessClient6
6 stub ObjectStublessClient7
7 stub ObjectStublessClient8
8 stub ObjectStublessClient9
9 stub ObjectStublessClient10
10 stub ObjectStublessClient11
11 stub ObjectStublessClient12
12 stub ObjectStublessClient13
13 stub ObjectStublessClient14
14 stub ObjectStublessClient15
15 stub ObjectStublessClient16
16 stub ObjectStublessClient17
17 stub ObjectStublessClient18
18 stub ObjectStublessClient19
19 stub ObjectStublessClient20
20 stub ObjectStublessClient21
21 stub ObjectStublessClient22
22 stub ObjectStublessClient23
23 stub ObjectStublessClient24
24 stub ObjectStublessClient25
25 stub ObjectStublessClient26
26 stub ObjectStublessClient27
27 stub ObjectStublessClient28
28 stub ObjectStublessClient29
29 stub ObjectStublessClient30
30 stub ObjectStublessClient31
31 stub ObjectStublessClient32
32 extern NdrProxyForwardingFunction3
33 extern NdrProxyForwardingFunction4
34 extern NdrProxyForwardingFunction5
35 extern NdrProxyForwardingFunction6
36 extern NdrProxyForwardingFunction7
37 extern NdrProxyForwardingFunction8
38 extern NdrProxyForwardingFunction9
39 extern NdrProxyForwardingFunction10
40 extern NdrProxyForwardingFunction11
41 extern NdrProxyForwardingFunction12
42 extern NdrProxyForwardingFunction13
43 extern NdrProxyForwardingFunction14
44 extern NdrProxyForwardingFunction15
45 extern NdrProxyForwardingFunction16
46 extern NdrProxyForwardingFunction17
47 extern NdrProxyForwardingFunction18
48 extern NdrProxyForwardingFunction19
49 extern NdrProxyForwardingFunction20
50 extern NdrProxyForwardingFunction21
51 extern NdrProxyForwardingFunction22
52 extern NdrProxyForwardingFunction23
53 extern NdrProxyForwardingFunction24
54 extern NdrProxyForwardingFunction25
55 extern NdrProxyForwardingFunction26
56 extern NdrProxyForwardingFunction27
57 extern NdrProxyForwardingFunction28
58 extern NdrProxyForwardingFunction29
59 extern NdrProxyForwardingFunction30
60 extern NdrProxyForwardingFunction31
61 extern NdrProxyForwardingFunction32
66 stdcall -noname CoGetSharedServiceId(ptr)
67 stdcall -noname CoAddRefSharedService(long)
68 stdcall -noname CoReleaseSharedService(long)
536 stub NdrOleInitializeExtension
69 stdcall -noname CoRegisterServerShutdownDelay(ptr long)
86 stdcall -noname CoBeginProcessEvents(ptr)
87 stdcall -noname CoMsgWaitInProcessEvents(ptr long ptr long long long)
88 stdcall -noname CoEndProcessEvents(ptr)
90 stdcall -noname RoGetDesignMode(ptr)
95 stdcall -noname CoSignalPendingGitRegistrationWaits()
110 stdcall -noname CoSetMessageDispatcher(ptr)
111 stdcall -noname CoHandlePriorityEventsFromMessagePump()
133 stdcall -noname RoIsASTAWorkScheduledAtPriorityOrHigher(long)
140 stdcall -noname CoAllowSetForegroundWindow(ptr ptr) ole32.CoAllowSetForegroundWindow
157 stdcall -noname RoGetDesignModeV2(ptr)
159 stdcall -noname RoGetExtensionRegistrationForLaunchContracts(ptr ptr long ptr ptr)
167 stdcall -noname CoGetCallContextOfObject(ptr ptr ptr)
168 stdcall -noname CoImpersonateClientOfObject(ptr ptr)
179 stdcall -noname RoInitializeStrict(long)
184 stdcall -noname CoGetCallLocality(ptr ptr)
82 stdcall RoFailFastWithErrorContextInternal2(long long ptr)
83 stub RoFailFastWithErrorContextInternal
84 stub UpdateProcessTracing
85 stdcall CLIPFORMAT_UserFree(ptr ptr)
91 stdcall CLIPFORMAT_UserMarshal(ptr ptr ptr)
105 stdcall CLIPFORMAT_UserSize(ptr long ptr)
107 stdcall CLIPFORMAT_UserUnmarshal(ptr ptr ptr)
109 stdcall CLSIDFromOle1Class(wstr ptr long)
113 stdcall CLSIDFromProgID(wstr ptr)
114 stdcall CLSIDFromProgIDEx(wstr ptr)
115 stdcall CLSIDFromString(wstr ptr)
249 stub CleanupOleStateInAllTls
251 stdcall CleanupTlsOleState(ptr)
252 stub ClearCleanupFlag
254 stdcall CoAddRefServerProcess()
255 stub CoAllowUnmarshalerCLSID
256 stub CoCancelCall
257 stdcall CoCopyProxy(ptr ptr)
258 stdcall CoCreateErrorInfo(ptr) CreateErrorInfo
259 stdcall CoCreateFreeThreadedMarshaler(ptr ptr)
260 stdcall CoCreateGuid(ptr)
261 stdcall CoCreateInstance(ptr ptr long ptr ptr)
262 stdcall CoCreateInstanceEx(ptr ptr long ptr long ptr)
264 stdcall CoCreateInstanceFromApp(ptr ptr long ptr long ptr)
266 stdcall CoCreateObjectInContext(ptr ptr ptr ptr)
267 stub CoDeactivateObject
268 stdcall CoDecodeProxy(long int64 ptr)
269 stdcall CoDecrementMTAUsage(ptr)
270 stdcall CoDisableCallCancellation(ptr)
271 stub CoDisconnectContext
272 stdcall CoDisconnectObject(ptr long)
273 stdcall CoEnableCallCancellation(ptr)
274 stdcall CoFileTimeNow(ptr)
275 stdcall CoFreeUnusedLibraries()
276 stdcall CoFreeUnusedLibrariesEx(long long)
277 stdcall CoGetActivationState(int128 long ptr)
278 stub CoGetApartmentID
279 stdcall CoGetApartmentType(ptr ptr)
280 stdcall CoGetCallContext(ptr ptr)
281 stdcall CoGetCallState(long ptr)
282 stdcall CoGetCallerTID(ptr)
283 stub CoGetCancelObject
284 stdcall CoGetClassObject(ptr long ptr ptr ptr)
286 stub CoGetClassVersion
287 stdcall CoGetContextToken(ptr)
288 stdcall CoGetCurrentLogicalThreadId(ptr)
289 stdcall CoGetCurrentProcess()
290 stdcall CoGetDefaultContext(long ptr ptr)
291 stdcall CoGetErrorInfo(long ptr) GetErrorInfo
292 stdcall CoGetInstanceFromFile(ptr ptr ptr long long wstr long ptr)
293 stdcall CoGetInstanceFromIStorage(ptr ptr ptr long ptr long ptr)
294 stdcall CoGetInterfaceAndReleaseStream(ptr ptr ptr)
295 stdcall CoGetMalloc(long ptr)
296 stdcall CoGetMarshalSizeMax(ptr ptr ptr long ptr long)
298 stub CoGetModuleType
299 stdcall CoGetObjectContext(ptr ptr)
300 stdcall CoGetPSClsid(ptr ptr)
301 stub CoGetProcessIdentifier
120 stdcall CoRegisterForApartmentShutdown(ptr ptr ptr) RoRegisterForApartmentShutdown
303 stdcall CoGetStdMarshalEx(ptr long ptr)
122 stdcall CoGetApartmentIdentifier(ptr)
305 stdcall CoGetTreatAsClass(ptr ptr)
306 stdcall CoImpersonateClient()
307 stdcall CoIncrementMTAUsage(ptr)
308 stdcall CoInitializeEx(ptr long)
309 stdcall CoInitializeSecurity(ptr long ptr ptr long long ptr long ptr)
310 stdcall CoInitializeWOW(long long)
311 stub CoInvalidateRemoteMachineBindings
312 stdcall CoIsHandlerConnected(ptr)
313 stdcall CoIsOle1Class(ptr)
314 stdcall CoLockObjectExternal(ptr long long)
315 stdcall CoMarshalHresult(ptr long)
316 stdcall CoMarshalInterThreadInterfaceInStream(ptr ptr ptr)
317 stdcall CoMarshalInterface(ptr ptr ptr long ptr long)
318 stub CoPopServiceDomain
319 stub CoPushServiceDomain
320 stub CoQueryAuthenticationServices
321 stdcall CoQueryClientBlanket(ptr ptr ptr ptr ptr ptr ptr)
322 stdcall CoQueryProxyBlanket(ptr ptr ptr ptr ptr ptr ptr ptr)
323 stub CoReactivateObject
324 stdcall CoRegisterActivationFilter(ptr)
112 stdcall CoRegisterChannelHook(ptr ptr)
325 stdcall CoRegisterClassObject(ptr ptr long long ptr)
328 stdcall CoRegisterInitializeSpy(ptr ptr)
329 stdcall CoRegisterMallocSpy(ptr)
330 stdcall CoRegisterMessageFilter(ptr ptr)
331 stdcall CoRegisterPSClsid(ptr ptr)
333 stdcall CoRegisterSurrogate(ptr)
334 stdcall CoRegisterSurrogateEx(ptr ptr)
335 stdcall CoReleaseMarshalData(ptr)
336 stdcall CoReleaseServerProcess()
337 stdcall CoResumeClassObjects()
338 stub CoRetireServer
339 stdcall CoRevertToSelf()
340 stdcall CoRevokeClassObject(long)
343 stdcall CoRevokeInitializeSpy(int64)
344 stdcall CoRevokeMallocSpy()
346 stub CoSetCancelObject
347 stdcall CoSetErrorInfo(long ptr) SetErrorInfo
348 stdcall CoSetOutgoingCallState(ptr ptr)
349 stdcall CoSetProxyBlanket(ptr long long ptr long long ptr long)
350 stdcall CoSuspendClassObjects()
351 stdcall CoSwitchCallContext(ptr ptr)
352 stdcall CoTaskMemAlloc(long)
353 stdcall CoTaskMemFree(ptr)
354 stdcall CoTaskMemRealloc(ptr long)
355 stub CoTestCancel
356 stdcall CoTreatAsClass(ptr ptr)
357 stdcall CoUninitialize()
358 stub CoUnloadingWOW
359 stdcall CoUnmarshalHresult(ptr ptr)
360 stdcall CoUnmarshalInterface(ptr ptr ptr)
361 stub CoVrfCheckThreadState
362 stub CoVrfGetThreadState
363 stub CoVrfReleaseThreadState
364 stdcall CoWaitForMultipleHandles(long long long ptr ptr)
365 stub CoWaitForMultipleObjects
366 stdcall CreateErrorInfo(ptr)
367 stdcall CreateStreamOnHGlobal(ptr long ptr)
368 stub DcomChannelSetHResult
369 stdcall DllDebugObjectRPCHook(long ptr)
370 stdcall DllGetActivationFactory(ptr ptr)
371 stdcall -private DllGetClassObject(ptr ptr ptr)
372 stub EnableHookObject
373 stdcall FreePropVariantArray(long ptr)
374 stub FreePropVariantArrayWorker
375 stub GetCatalogHelper
376 stdcall GetErrorInfo(long ptr)
377 stub GetFuncDescs
378 stdcall GetHGlobalFromStream(ptr ptr)
379 stub GetHookInterface
380 stdcall GetRestrictedErrorInfo(ptr)
381 stdcall HACCEL_UserFree(ptr ptr)
382 stdcall -arch=win64 HACCEL_UserFree64(ptr ptr) HACCEL_UserFree
383 stdcall HACCEL_UserMarshal(ptr ptr ptr)
384 stdcall -arch=win64 HACCEL_UserMarshal64(ptr ptr ptr) HACCEL_UserMarshal
385 stdcall HACCEL_UserSize(ptr long ptr)
386 stdcall -arch=win64 HACCEL_UserSize64(ptr long ptr) HACCEL_UserSize
387 stdcall HACCEL_UserUnmarshal(ptr ptr ptr)
388 stdcall -arch=win64 HACCEL_UserUnmarshal64(ptr ptr ptr) HACCEL_UserUnmarshal
389 stdcall HBITMAP_UserFree(ptr ptr)
391 stdcall HBITMAP_UserMarshal(ptr ptr ptr)
393 stdcall HBITMAP_UserSize(ptr long ptr)
395 stdcall HBITMAP_UserUnmarshal(ptr ptr ptr)
397 stdcall HBRUSH_UserFree(ptr ptr)
399 stdcall HBRUSH_UserMarshal(ptr ptr ptr)
401 stdcall HBRUSH_UserSize(ptr long ptr)
403 stdcall HBRUSH_UserUnmarshal(ptr ptr ptr)
405 stdcall HDC_UserFree(ptr ptr)
407 stdcall HDC_UserMarshal(ptr ptr ptr)
409 stdcall HDC_UserSize(ptr long ptr)
411 stdcall HDC_UserUnmarshal(ptr ptr ptr)
413 stdcall HGLOBAL_UserFree(ptr ptr)
414 stdcall -arch=win64 HGLOBAL_UserFree64(ptr ptr) HGLOBAL_UserFree
415 stdcall HGLOBAL_UserMarshal(ptr ptr ptr)
417 stdcall HGLOBAL_UserSize(ptr long ptr)
419 stdcall HGLOBAL_UserUnmarshal(ptr ptr ptr)
421 stdcall HICON_UserFree(ptr ptr)
422 stdcall -arch=win64 HICON_UserFree64(ptr ptr) HICON_UserFree
423 stdcall HICON_UserMarshal(ptr ptr ptr)
424 stdcall -arch=win64 HICON_UserMarshal64(ptr ptr ptr) HICON_UserMarshal
425 stdcall HICON_UserSize(ptr long ptr)
426 stdcall -arch=win64 HICON_UserSize64(ptr long ptr) HICON_UserSize
427 stdcall HICON_UserUnmarshal(ptr ptr ptr)
428 stdcall -arch=win64 HICON_UserUnmarshal64(ptr ptr ptr) HICON_UserUnmarshal
429 stdcall HMENU_UserFree(ptr ptr)
430 stdcall -arch=win64 HMENU_UserFree64(ptr ptr) HMENU_UserFree
431 stdcall HMENU_UserMarshal(ptr ptr ptr)
432 stdcall -arch=win64 HMENU_UserMarshal64(ptr ptr ptr) HMENU_UserMarshal
433 stdcall HMENU_UserSize(ptr long ptr)
434 stdcall -arch=win64 HMENU_UserSize64(ptr long ptr) HMENU_UserSize
435 stdcall HMENU_UserUnmarshal(ptr ptr ptr)
436 stdcall -arch=win64 HMENU_UserUnmarshal64(ptr ptr ptr) HMENU_UserUnmarshal
437 stdcall HMONITOR_UserFree(ptr ptr)
438 stdcall -arch=win64 HMONITOR_UserFree64(ptr ptr) HMONITOR_UserFree
439 stdcall HMONITOR_UserMarshal(ptr ptr ptr)
440 stdcall -arch=win64 HMONITOR_UserMarshal64(ptr ptr ptr) HMONITOR_UserMarshal
441 stdcall HMONITOR_UserSize(ptr long ptr)
442 stdcall -arch=win64 HMONITOR_UserSize64(ptr long ptr) HMONITOR_UserSize
443 stdcall HMONITOR_UserUnmarshal(ptr ptr ptr)
444 stdcall -arch=win64 HMONITOR_UserUnmarshal64(ptr ptr ptr) HMONITOR_UserUnmarshal
445 stdcall HPALETTE_UserFree(ptr ptr)
447 stdcall HPALETTE_UserMarshal(ptr ptr ptr)
449 stdcall HPALETTE_UserSize(ptr long ptr)
451 stdcall HPALETTE_UserUnmarshal(ptr ptr ptr)
453 stdcall HSTRING_UserFree(ptr ptr)
454 stdcall -arch=win64 HSTRING_UserFree64(ptr ptr)
455 stdcall HSTRING_UserMarshal(ptr ptr ptr)
456 stdcall -arch=win64 HSTRING_UserMarshal64(ptr ptr ptr)
457 stdcall HSTRING_UserSize(ptr long ptr)
458 stdcall -arch=win64 HSTRING_UserSize64(ptr long ptr)
459 stdcall HSTRING_UserUnmarshal(ptr ptr ptr)
460 stdcall -arch=win64 HSTRING_UserUnmarshal64(ptr ptr ptr)
461 stdcall HWND_UserFree(ptr ptr)
462 stdcall -arch=win64 HWND_UserFree64(ptr ptr) HWND_UserFree
463 stdcall HWND_UserMarshal(ptr ptr ptr)
464 stdcall -arch=win64 HWND_UserMarshal64(ptr ptr ptr) HWND_UserMarshal
465 stdcall HWND_UserSize(ptr long ptr)
466 stdcall -arch=win64 HWND_UserSize64(ptr long ptr) HWND_UserSize
467 stdcall HWND_UserUnmarshal(ptr ptr ptr)
468 stdcall -arch=win64 HWND_UserUnmarshal64(ptr ptr ptr) HWND_UserUnmarshal
469 stub HkOleRegisterObject
470 stdcall IIDFromString(wstr ptr)
471 stub InternalAppInvokeExceptionFilter
474 stub InternalCCFreeUnused
475 stub InternalCCGetClassInformationForDde
476 stub InternalCCGetClassInformationFromKey
477 stub InternalCCSetDdeServerWindow
478 stub InternalCMLSendReceive
483 stub InternalCallAsProxyExceptionFilter
484 stub InternalCallFrameExceptionFilter
485 stub InternalCallerIsAppContainer
486 stub InternalCanMakeOutCall
488 stub InternalCoIsSurrogateProcess
489 stub InternalCoRegisterDisconnectCallback
490 stub InternalCoRegisterSurrogatedObject
491 stdcall InternalCoStdMarshalObject(ptr long ptr ptr)
492 stub InternalCoUnregisterDisconnectCallback
493 stub InternalCompleteObjRef
494 stub InternalCreateCAggId
495 stub InternalCreateIdentityHandler
496 stub InternalDoATClassCreate
497 stub InternalFillLocalOXIDInfo
498 stub InternalFreeObjRef
499 stub InternalGetWindowPropInterface
501 stdcall InternalIrotEnumRunning(ptr)
503 stdcall InternalIrotGetObject(ptr ptr ptr)
506 stdcall InternalIrotGetTimeOfLastChange(ptr ptr)
508 stdcall InternalIrotIsRunning(ptr)
510 stdcall InternalIrotNoteChangeTime(long ptr)
511 stdcall InternalIrotRegister(ptr ptr ptr ptr long ptr ptr)
512 stdcall InternalIrotRevoke(long ptr ptr ptr)
513 stub InternalIsApartmentInitialized
514 stdcall InternalIsProcessInitialized()
515 stub InternalMarshalObjRef
516 stub InternalNotifyDDStartOrStop
518 stub InternalOleModalLoopBlockFn
520 stub InternalRegisterWindowPropInterface
522 stub InternalReleaseMarshalObjRef
524 stub InternalSTAInvoke
525 stub InternalServerExceptionFilter
526 stub InternalSetAptCallCtrlOnTlsIfRequired
527 stub InternalSetOleThunkWowPtr
528 stub InternalStubInvoke
529 stdcall InternalTlsAllocData(ptr)
530 stub InternalUnmarshalObjRef
531 stub IsErrorPropagationEnabled
534 stub NdrExtStubInitialize
535 stub NdrOleDllGetClassObject
537 stub NdrpFindInterface
538 stdcall ProgIDFromCLSID(ptr ptr)
539 stdcall PropVariantClear(ptr)
540 stdcall PropVariantCopy(ptr ptr)
541 stub ReleaseFuncDescs
542 stdcall RoActivateInstance(ptr ptr)
543 stub RoCaptureErrorContext
544 stub RoClearError
545 stdcall RoFailFastWithErrorContext(long)
546 stub RoFreeParameterizedTypeExtra
547 stub RoGetActivatableClassRegistration
548 stdcall RoGetActivationFactory(ptr ptr ptr)
549 stdcall RoGetAgileReference(long ptr ptr ptr)
550 stdcall RoGetApartmentIdentifier(ptr)
551 stdcall RoGetErrorReportingFlags(ptr)
552 stdcall RoGetMatchingRestrictedErrorInfo(long ptr)
553 stdcall RoGetParameterizedTypeInstanceIID(long ptr ptr ptr ptr)
302 stdcall CoGetStandardMarshal(ptr ptr long ptr long ptr)
555 stdcall RoInitialize(long)
556 stub RoInspectCapturedStackBackTrace
557 stub RoInspectThreadErrorInfo
558 stdcall RoOriginateError(long ptr)
559 stdcall RoOriginateErrorW(long long ptr)
560 stdcall RoOriginateLanguageException(long ptr ptr)
561 stub RoParameterizedTypeExtraGetTypeSignature
562 stdcall RoRegisterActivationFactories(ptr ptr long ptr)
563 stdcall RoRegisterForApartmentShutdown(ptr ptr ptr)
564 stub RoReportCapabilityCheckFailure
565 stub RoReportFailedDelegate
566 stdcall RoReportUnhandledError(ptr)
567 stub RoResolveRestrictedErrorInfoReference
568 stdcall RoRevokeActivationFactories(ptr)
569 stdcall RoSetErrorReportingFlags(long)
570 stdcall RoTransformError(long long ptr)
571 stdcall RoTransformErrorW(long long long ptr)
572 stdcall RoUninitialize()
573 stub RoUnregisterForApartmentShutdown
574 stub SetCleanupFlag
575 stdcall SetErrorInfo(long ptr)
576 stdcall SetRestrictedErrorInfo(ptr)
577 stdcall StringFromCLSID(ptr ptr)
578 stdcall StringFromGUID2(ptr ptr long)
579 stdcall StringFromIID(ptr ptr) StringFromCLSID
580 stub UpdateDCOMSettings
581 stdcall WdtpInterfacePointer_UserFree(ptr)
582 stub -arch=win64 WdtpInterfacePointer_UserFree64
583 stdcall WdtpInterfacePointer_UserMarshal(ptr long ptr ptr ptr)
584 stub -arch=win64 WdtpInterfacePointer_UserMarshal64
585 stdcall WdtpInterfacePointer_UserSize(ptr long long ptr ptr)
586 stub -arch=win64 WdtpInterfacePointer_UserSize64
587 stdcall WdtpInterfacePointer_UserUnmarshal(ptr ptr ptr ptr)
588 stub -arch=win64 WdtpInterfacePointer_UserUnmarshal64
589 stdcall WindowsCompareStringOrdinal(ptr ptr ptr)
590 stdcall WindowsConcatString(ptr ptr ptr)
591 stdcall WindowsCreateString(wstr long ptr)
592 stdcall WindowsCreateStringReference(wstr long ptr ptr)
593 stdcall WindowsDeleteString(ptr)
594 stdcall WindowsDeleteStringBuffer(ptr)
595 stdcall WindowsDuplicateString(ptr ptr)
596 stdcall WindowsGetStringLen(ptr)
597 stdcall WindowsGetStringRawBuffer(ptr ptr)
598 stub WindowsInspectString
600 stdcall WindowsIsStringEmpty(ptr)
601 stdcall WindowsPreallocateStringBuffer(long ptr ptr)
602 stdcall WindowsPromoteStringBuffer(ptr ptr)
603 stub WindowsReplaceString
604 stdcall WindowsStringHasEmbeddedNull(ptr ptr)
605 stdcall WindowsSubstring(ptr long ptr)
606 stdcall WindowsSubstringWithSpecifiedLength(ptr long long ptr)
607 stdcall WindowsTrimStringEnd(ptr ptr ptr)
608 stdcall WindowsTrimStringStart(ptr ptr ptr)
304 stdcall CoGetSystemSecurityPermissions(long ptr)
554 stdcall RoGetServerActivatableClasses(ptr ptr ptr)
