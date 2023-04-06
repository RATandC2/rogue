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
	D_API( RtlReAllocateHeap );
	D_API( RtlAllocateHeap );
	D_API( RtlCompactHeap );
	D_API( RtlFreeHeap );
	D_API( RtlSizeHeap );
	D_API( RtlZeroHeap );
} API ;

/* API Hashes */
#define H_API_RTLREALLOCATEHEAP		0xaf740371 /* RtlReAllocateHeap */
#define H_API_RTLALLOCATEHEAP		0x3be94c5a /* RtlAllocateHeap */
#define H_API_RTLCOMPACTHEAP		0xccd9c63c /* RtlCompactHeap */
#define H_API_RTLFREEHEAP		0x73a9e4d7 /* RtlFreeHeap */
#define H_API_RTLSIZEHEAP		0xef31e6b0 /* RtlSizeHeap */
#define H_API_RTLZEROHEAP		0x1f2175d5 /* RtlZeroHeap */

/* LIB Hashes */
#define H_LIB_NTDLL			0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Re-allocates a buffer.
 *
!*/
D_SEC( B ) PVOID MemoryReAlloc( _In_ PVOID Buffer, _In_ SIZE_T Length )
{
	API		Api;
	PVOID		Mem = NULL;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	/* Get pointer and execute */
	Api.RtlReAllocateHeap = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLREALLOCATEHEAP ) );
	Mem = Api.RtlReAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Buffer, Length );

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	/* Return a pointer */
	return C_PTR( Mem );
};

/*!
 *
 * Purpose:
 *
 * Allocate a buffer.
 *
!*/
D_SEC( B ) PVOID MemoryAlloc( _In_ SIZE_T Length )
{
	API	Api;
	PVOID	Mem = NULL;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	/* Get pointer and execute */
	Api.RtlAllocateHeap = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLALLOCATEHEAP ) );
	Mem = Api.RtlAllocateHeap( NtCurrentPeb()->ProcessHeap, HEAP_ZERO_MEMORY, Length );

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	/* Return a pointer */
	return C_PTR( Mem );
};

/*!
 *
 * Purpose:
 *
 * Free a buffer.
 *
!*/
D_SEC( B ) BOOL MemoryFree( _In_ PVOID Buffer )
{
	API	Api;

	SIZE_T	Len = 0;
	BOOLEAN	Ret = FALSE;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	
	Api.RtlCompactHeap = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLCOMPACTHEAP ) );
	Api.RtlFreeHeap    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLFREEHEAP ) );
	Api.RtlSizeHeap    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLSIZEHEAP ) );
	Api.RtlZeroHeap    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLZEROHEAP ) );

	/* Is this a valid buffer? */
	if ( ( Len = Api.RtlSizeHeap( NtCurrentPeb()->ProcessHeap, 0, Buffer ) ) != -1 ) {
		/* Zero out the buffer */
		RtlZeroMemory( Buffer, Len );

		/* Free the buffer */
		Ret = Api.RtlFreeHeap( NtCurrentPeb()->ProcessHeap, 0, Buffer ); 
	};

	/* Compcat the heap */
	Api.RtlCompactHeap( NtCurrentPeb()->ProcessHeap, 0 );

	/* Zero out the heap */
	Api.RtlZeroHeap( NtCurrentPeb()->ProcessHeap, 0 );

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );

	/* Return a value */
	return Ret;
};
