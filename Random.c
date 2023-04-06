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

ULONG
NTAPI
RtlRandomEx(
	PUINT32 Seed
);

typedef struct
{
	D_API( RtlRandomEx );
} API ;

/* API Hashes */
#define H_API_RTLRANDOMEX		0x7f1224f5 /* RtlRandomEx */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Generates a random integer
 *
!*/
D_SEC( B ) UINT32 RandomInt32( VOID ) 
{
	API	Api;
	UINT32	Val = 0;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	Api.RtlRandomEx = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLRANDOMEX ) );

	/* Create a random integer */
	Val = Api.RtlRandomEx( &Val );
	Val = Api.RtlRandomEx( &Val );

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	/* Return a UINT32 integer */
	return Val;
};

/*!
 *
 * Purpose:
 *
 * Generates a random number in between a range.
 *
!*/
D_SEC( B ) UINT32 RandomIntRng( _In_ UINT32 Min, _In_ UINT32 Max )
{
	API	Api;
	UINT32	Val = 0;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	Api.RtlRandomEx = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLRANDOMEX ) );

	/* Create a random integer */
	Val = Api.RtlRandomEx( &Val );
	Val = Api.RtlRandomEx( &Val );

	/* Generate a value in a range */
	Val = ( Val % ( Max - Min + 1 ) ) + Min;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );

	/* Return value */
	return Val;
};
