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
 * Finds the base address of a module that is
 * in memory.
 *
!*/
D_SEC( B ) PVOID PebGetModule( _In_ UINT32 ImageHash );
