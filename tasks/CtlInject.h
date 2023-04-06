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
 * Injects a specified process with the shellcode.
 *
!*/
D_SEC( B ) BOOLEAN CtlInject( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _Out_ PBUFFER Output );
