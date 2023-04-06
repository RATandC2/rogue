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
 * Creates the initial hello packet, and stores it in the
 * output buffer. Attempts to initialize the context 
 * structure.
 *
!*/
D_SEC( B ) BOOL Init( _In_ PROGUE_CTX Context, _In_ PBUFFER Output );
