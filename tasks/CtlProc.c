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
	D_API( NtQuerySystemInformation );
} API ;

/* API Hashes */
#define H_API_NTQUERYSYSTEMINFORMATION		0x7bc23928 /* NtQuerySystemInformation */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Returns a formatted string containing a snapshot
 * of any running process's at the time of the 
 * execution.
 *
!*/
D_SEC( B ) BOOLEAN CtlProc( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _Out_ PBUFFER Output )
{
	API				Api;

	SIZE_T				Len = 0;
	BOOLEAN				Pus = FALSE;
	BOOLEAN				Ret = FALSE;
	NTSTATUS			Nst = STATUS_UNSUCCESSFUL;

	PCHAR				Int = NULL;
	PCHAR				Arc = NULL;
	PCHAR				Usr = NULL;
	PCHAR				Dmn = NULL;
	PBUFFER				Out = NULL;
	PSYSTEM_PROCESS_INFORMATION	Tmp = NULL;
	PSYSTEM_PROCESS_INFORMATION	Spi = NULL;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	Api.NtQuerySystemInformation = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYSYSTEMINFORMATION ) );

	/* Create the output buffer */
	if ( ( Out = BufferCreate() ) != NULL ) {
		/* Query the length of the buffer needed */
		if ( ! NT_SUCCESS( ( Nst = Api.NtQuerySystemInformation( SystemProcessInformation, NULL, 0, &Len ) ) ) ) {
			if ( ( Spi = MemoryAlloc( Len ) ) != NULL ) {
				/* Fill the buffer */
				if ( NT_SUCCESS( ( Nst = Api.NtQuerySystemInformation( SystemProcessInformation, Spi, Len, &Len ) ) ) ) {
					Tmp = C_PTR( Spi );

					/* Iterate over every entry */
					while ( Tmp->NextEntryOffset != 0 ) {
						if ( Tmp->ImageName.Buffer != NULL ) {
							/* Pull the process arch, integrity, username, and domain */
							Int = ProcIntegrityStr( Tmp->UniqueProcessId );
							Arc = ProcArchStr( Tmp->UniqueProcessId );
							Pus = ProcUserStr( Tmp->UniqueProcessId, &Usr, &Dmn );

							/* Print information about the process */
							BufferPrintf( Out, C_PTR( G_PTR( "%S\t%hu\t%hu\t%hu\t%s\t%s\t%s%s%s\n" ) ),
								      Tmp->ImageName.Buffer,
								      Tmp->UniqueProcessId,
								      Tmp->InheritedFromUniqueProcessId,
								      Tmp->SessionId,
								      Arc != NULL ? Arc : C_PTR( G_PTR( "" ) ),
								      Int != NULL ? Int : C_PTR( G_PTR( "" ) ),
								      Pus != FALSE && Dmn != NULL ? Dmn : C_PTR( G_PTR( "" ) ),
								      Pus != FALSE && Dmn != NULL ? C_PTR( G_PTR( "\\" ) ) : C_PTR( G_PTR( "" ) ),
								      Pus != FALSE && Usr != NULL ? Usr : C_PTR( G_PTR( "" ) ) );

							if ( Pus != FALSE ) {
								/* Free the domain and username string */
								MemoryFree( Dmn );
								MemoryFree( Usr );
							};
						};
						/* Move onto the next entry */
						Tmp = C_PTR( U_PTR( Tmp ) + Tmp->NextEntryOffset );
					};
				} else
				{
					/* Whatever error was returned */
					NtCurrentTeb()->LastErrorValue = Nst;
				};
				/* Free the memory! */
				MemoryFree( Spi );
			} else
			{
				/* Out of memory */
				NtCurrentTeb()->LastErrorValue = STATUS_NO_MEMORY;
			};
		} else
		{
			/* Whatever error was returned */
			NtCurrentTeb()->LastErrorValue = Nst;
		};
		/* Do we have an output buffer? */
		if ( Out->Buffer != NULL ) {
			Ret = BufferAddRaw( Output, Out->Buffer, Out->Length );
		}
		/* Clear the outpuut buffer */
		BufferClear( Out );
	} else
	{
		/* Out of memory */
		NtCurrentTeb()->LastErrorValue = STATUS_NO_MEMORY;
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	/* Return Status */
	return Ret;
};
