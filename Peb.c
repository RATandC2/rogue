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
 * Finds the base address of a module that is
 * in memory.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 ImageHash )
{
	PLIST_ENTRY		Hdr = NULL; 
	PLIST_ENTRY		Ent = NULL;
	PLDR_DATA_TABLE_ENTRY	Ldr = NULL;

	/* Get a pointer to the first entry and header */
	Hdr = & NtCurrentPeb()->Ldr->InLoadOrderModuleList;
	Ent = Hdr->Flink;

	/* Enumerate the entire list */
	for ( ; Ent != Hdr ; Ent = Ent->Flink ) {
		/* Get a pointer to the linked list */
		Ldr = C_PTR( CONTAINING_RECORD( Ent, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks ) );

		/* Is this our target image name */
		if ( HashString( Ldr->BaseDllName.Buffer, Ldr->BaseDllName.Length ) == ImageHash ) {
			return C_PTR( Ldr->DllBase );
		};
	};
	/* Return no pointer */
	return NULL;
};
