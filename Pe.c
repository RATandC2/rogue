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

/*!
 *
 * Purpose:
 *
 * Searches a PE for an export.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 ExportHash )
{
	PUINT32			Aon = NULL;
	PUINT32			Aof = NULL;
	PUINT16			Aoo = NULL;
	PIMAGE_DOS_HEADER	Dos = NULL;
	PIMAGE_NT_HEADERS	Nth = NULL;
	PIMAGE_DATA_DIRECTORY	Dir = NULL;
	PIMAGE_EXPORT_DIRECTORY	Exp = NULL;

	/* Get pointers to the headers */
	Dos = C_PTR( ImageBase );
	Nth = C_PTR( U_PTR( Dos ) + Dos->e_lfanew );
	Dir = & Nth->OptionalHeader.DataDirectory[ IMAGE_DIRECTORY_ENTRY_EXPORT ];

	/* Does the export directory exist? */
	if ( Dir->VirtualAddress != 0 ) {
		/* Set export table address pointers */
		Exp = C_PTR( U_PTR( Dos ) + Dir->VirtualAddress );
		Aon = C_PTR( U_PTR( Dos ) + Exp->AddressOfNames );
		Aof = C_PTR( U_PTR( Dos ) + Exp->AddressOfFunctions );
		Aoo = C_PTR( U_PTR( Dos ) + Exp->AddressOfNameOrdinals );

		/* Enumerate the PE's export directory */
		for ( INT Idx = 0 ; Idx < Exp->NumberOfNames ; ++Idx ) {
			/* Is this our export? */
			if ( HashString( C_PTR( U_PTR( Dos ) + Aon[ Idx ] ), 0 ) == ExportHash ) {
				/* Return a pointer to the export */
				return C_PTR( U_PTR( Dos ) + Aof[ Aoo[ Idx ] ] );
			};
		};
	};
	/* Return a pointer */
	return NULL;
};
