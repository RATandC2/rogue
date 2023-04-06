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
 * Allow rogue to morph itself in memory, and go to 'sleep'
 * before awaking from its slumber to download more tasks
 * and execute them accordingly. Or it will if you add this
 * code.
 *
!*/
D_SEC( B ) VOID Hide( _In_ UINT32 SleepTime );
