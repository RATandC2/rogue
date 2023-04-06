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
	PVOID	Buffer;
	SIZE_T	Length;
} BUFFER, *PBUFFER ;

/*!
 *
 * Purpose:
 *
 * Allocates a 'buffer' object on the heap.
 *
!*/
D_SEC( B ) PBUFFER BufferCreate( VOID );

/*!
 *
 * Purpose:
 *
 * Frees a buffers pointers and its object.
 *
!*/
D_SEC( B ) VOID BufferClear( _In_ PBUFFER Buffer );

/*!
 *
 * Purpose:
 *
 * Appends a raw buffer.
 *
!*/
D_SEC( B ) BOOL BufferAddRaw( _In_ PBUFFER BufferObj, _In_ PVOID Buffer, _In_ ULONG Length );

/*!
 *
 * Purpose:
 *
 * Extends a raw buffer 
 *
!*/
D_SEC( B ) BOOL BufferExtend( _In_ PBUFFER BufferObj, _In_ ULONG Length );

/*!
 *
 * Purpose:
 *
 * Resets a buffer.
 *
!*/
D_SEC( B ) BOOL BufferReset( _In_ PBUFFER BufferObj );

/*!
 *
 * Purpose:
 *
 * Formats a string onto a buffer.
 *
!*/
D_SEC( B ) BOOL BufferPrintf( _In_ PBUFFER BufferObj, _In_ PCHAR Format, ... );
