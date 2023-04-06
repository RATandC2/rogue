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

#ifndef EXIT_MODE_PROCESS
#define EXIT_MODE_PROCESS	0
#endif

#ifndef EXIT_MODE_THREAD	
#define EXIT_MODE_THREAD	1
#endif

#ifndef EXIT_MODE_THREAD_FREE	
#define EXIT_MODE_THREAD_FREE	2	
#endif

#ifndef EXIT_MODE_NONE
#define EXIT_MODE_NONE		3
#endif

/*!
 *
 * Purpose:
 *
 * Exits depending on the requested configuration
 *
!*/
D_SEC( B ) VOID Exit( _In_ UINT32 ExitMode );
