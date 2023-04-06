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
	D_API( _vsnprintf );
} API ;

/* API Hashes */
#define H_API_VSNPRINTF		0xa59022ce /* _vsnprintf */

/* LIB Hashes */
#define H_LIB_NTDLL		0x1edab0ed /* ntdll.dll */	

/*!
 *
 * Purpose:
 *
 * Allocates a 'buffer' object on the heap.
 *
!*/
D_SEC( B ) PBUFFER BufferCreate( VOID )
{
	PBUFFER	Buf = NULL;

	/* Allocate a buffer object */
	if ( ( Buf = MemoryAlloc( sizeof( BUFFER ) ) ) != NULL ) {
		/* Set the initial values */
		Buf->Buffer = NULL;
		Buf->Length = 0;
	};

	/* Return a buffer */
	return C_PTR( Buf );
};

/*!
 *
 * Purpose:
 *
 * Frees a buffers pointers and its object.
 *
!*/
D_SEC( B ) VOID BufferClear( _In_ PBUFFER Buffer )
{
	if ( Buffer != NULL ) {
		if ( Buffer->Buffer != NULL ) {
			/* Free the buffer */
			MemoryFree( Buffer->Buffer );
		};
		/* Free the buffer */
		MemoryFree( Buffer );
	};
};

/*!
 *
 * Purpose:
 *
 * Appends a raw buffer.
 *
!*/
D_SEC( B ) BOOL BufferAddRaw( _In_ PBUFFER BufferObj, _In_ PVOID Buffer, _In_ ULONG Length )
{
	PVOID	Ptr = NULL;
	BOOL	Ret = FALSE;

	if ( BufferObj->Buffer != NULL ) {
		/* Re-allocate a buffer */
		Ptr = MemoryReAlloc( BufferObj->Buffer, BufferObj->Length + Length );
	} else {
		/* Create a fresh buffer! */
		Ptr = MemoryAlloc( Length );
	};

	if ( Ptr != NULL ) {
		/* Set new pointer */
		BufferObj->Buffer = C_PTR( Ptr );

		if ( Buffer != NULL ) {
			/* Copy over user data */
			__builtin_memcpy( C_PTR( U_PTR( BufferObj->Buffer ) + BufferObj->Length ), Buffer, Length );
		};

		/* Update new length */
		BufferObj->Length = BufferObj->Length + Length;

		/* Return Status */
		Ret = TRUE;
	};
	/* Return */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Extends a raw buffer 
 *
!*/
D_SEC( B ) BOOL BufferExtend( _In_ PBUFFER BufferObj, _In_ ULONG Length )
{
	/* Extends the buffer */
	return BufferAddRaw( BufferObj, NULL, Length );
};

/*!
 *
 * Purpose:
 *
 * Resets a buffer.
 *
!*/
D_SEC( B ) BOOL BufferReset( _In_ PBUFFER BufferObj )
{
	BOOLEAN	Ret = FALSE;

	if ( BufferObj->Buffer != NULL ) {
		/* Attempt to free the buffer! */
		Ret = MemoryFree( BufferObj->Buffer );

		/* Reset the original values on success! */
		BufferObj->Buffer = Ret != FALSE ? NULL : BufferObj->Buffer;
		BufferObj->Length = Ret != FALSE ? 0 : BufferObj->Length;
	};

	/* Return STatus */
	return Ret;
};

/*!
 *
 * Purpose:
 *
 * Formats a string onto a buffer.
 *
!*/
D_SEC( B ) BOOL BufferPrintf( _In_ PBUFFER BufferObj, _In_ PCHAR Format, ... )
{
	API	Api;
	va_list	Lst;

	UINT32	Len = 0;
	BOOLEAN	Ret = FALSE;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Lst, sizeof( Lst ) );

	Api._vsnprintf = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_VSNPRINTF ) );

	/* Get the length of the buffer */
	va_start( Lst, Format );
	Len = Api._vsnprintf( NULL, 0, Format, Lst );
	va_end( Lst );

	/* Extend to support the string at the end */
	if ( BufferExtend( BufferObj, Len ) ) {
		/* Format the string onto the buffer */
		va_start( Lst, Format );
		Len = Api._vsnprintf( C_PTR( U_PTR( BufferObj->Buffer ) + BufferObj->Length - Len ), Len, Format, Lst );
		va_end( Lst );

		/* Set the status */
		Ret = TRUE;
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Lst, sizeof( Lst ) );

	/* Return Status */
	return Ret;
};
