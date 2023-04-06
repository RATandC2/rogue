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
 * Returns a formatted string containing a snapshot
 * of any running process's at the time of the 
 * execution.
 *
!*/
D_SEC( B ) BOOLEAN CtlProc( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _Out_ PBUFFER Output );
