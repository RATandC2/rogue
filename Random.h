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
 * Generates a random integer
 *
!*/
D_SEC( B ) UINT32 RandomInt32( VOID );

/*!
 *
 * Purpose:
 *
 * Generates a random number in between a range.
 *
!*/
D_SEC( B ) UINT32 RandomIntRng( _In_ UINT32 Min, _In_ UINT32 Max );
