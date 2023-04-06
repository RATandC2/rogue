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
 * Searches a PE for an export.
 *
!*/
D_SEC( B ) PVOID PeGetFuncEat( _In_ PVOID ImageBase, _In_ UINT32 ExportHash );
