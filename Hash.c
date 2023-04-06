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
 * Constructs a DJB2 hash representation of 
 * a string.
 *
!*/
D_SEC( B ) UINT32 HashString( _In_ PVOID Buffer, _In_opt_ UINT32 Length )
{
	UINT8	Chr = 0;
	UINT32	Djb = 5381;
	PUINT8	Ptr = NULL;

	/* Set the initial buffer */
	Ptr = C_PTR( Buffer );

	while ( TRUE ) {
		/* Get the current character */
		Chr = * Ptr;

		/* Is no length provided ? */
		if ( ! Length ) {
			/* NULL terminated */
			if ( ! * Ptr ) {
				/* Reached a null terminator. Abort */
				break;
			};
		} else {
			/* Did our position exceed the buffer? */
			if ( ( UINT32 )( Ptr - ( PUINT8 ) Buffer ) >= Length ) {
				/* Exceeded the length the buffer */
				break;
			};
			/* NULL character? */
			if ( ! * Ptr ) {
				/* Increment and continue */
				++Ptr; continue;
			};
		};
		/* Is this a lowercase character? */
		if ( Chr >= 'a' ) {
			/* Decrement to uppercase */
			Chr -= 0x20;
		};

		/* Create the character */
		Djb = ( ( Djb << 5 ) + Djb ) + Chr; ++Ptr;
	};
	/* Return the hash */
	return Djb ^ E_HSH_KEY;
};
