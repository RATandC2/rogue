/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#pragma once

/*!
 *
 * Purpose:
 *
 * Re-allocates a buffer.
 *
!*/
D_SEC( B ) PVOID MemoryReAlloc( _In_ PVOID Buffer, _In_ SIZE_T Length );

/*!
 *
 * Purpose:
 *
 * Allocate a buffer.
 *
!*/
D_SEC( B ) PVOID MemoryAlloc( _In_ SIZE_T Length );

/*!
 *
 * Purpose:
 *
 * Free a buffer.
 *
!*/
D_SEC( B ) BOOL MemoryFree( _In_ PVOID Buffer );
