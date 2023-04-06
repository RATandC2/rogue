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

/* Gets a pointer to the function  / var / string via its relative offset to GetIp */
#define G_PTR( x )	( ULONG_PTR ) ( GetIp( ) - ( ( ULONG_PTR ) & GetIp - ( ULONG_PTR ) x ) )

/* Cast as a global function or variable in a specific section*/
#define D_SEC( x )	__attribute__(( __section__( ".text$" #x ) ))

/* Cast as a pointer with a specific typedef */
#define D_API( x )	__typeof__( x ) * x

/* Decrypt an encrypted DJB2 value */
#define E_HSH( x )	( x ^ E_HSH_KEY )

/* Cast as a C pointer-wide integer */
#define U_PTR( x )	( ( ULONG_PTR ) x )

/* Cast as a C pointer */
#define C_PTR( x )	( ( PVOID ) x )
