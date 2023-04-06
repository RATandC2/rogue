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
 * Returns a pointer to a string representing the
 * integrity of the target process if it is able
 * to be pulled.
 *
 * if NULL is returned, it was unable to determine
 * the process integrity.
 *
!*/
D_SEC( B ) PCHAR ProcIntegrityStr( _In_ UINT32 ProcessId );

/*!
 *
 * Purpose:
 *
 * Returns a pointer to a string representing the
 * architecture of the target process if it is
 * able to be pulled.
 *
 * If NULL is returned, it was unable to determine
 * the process architecture.
 *
!*/
D_SEC( B ) PCHAR ProcArchStr( _In_ UINT32 ProcessId );

/*!
 *
 * Purpose:
 *
 * Returns a string representing the username for
 * the current process. if NULL is returned, it
 * means it could not pull the username from the
 * token.
 *
 * Result must be freed from memory.
 *
!*/
D_SEC( B ) BOOL ProcUserStr( _In_ UINT32 ProcessId, _Out_ PCHAR* Username, _Out_ PCHAR* WgDomain );
