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

typedef struct __attribute__(( packed ))
{
	UINT32	Jitter;
	UINT32	Sleep;
	UINT32	ExitMode;
	UINT32	IpAddr;
	UINT32	ChkLen;
	UINT32	WaitTm;
	UINT32	KeyLen;
	UINT8	KeyBuf[ 0 ];
} CONFIG, *PCONFIG ;
