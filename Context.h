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

typedef struct
{
	UINT32	JitterNum;
	UINT32	SleepTime;
	UINT32	ExitMode;	
} ROGUE_CNF, *PROGUE_CNF ;

typedef struct
{
	BOOLEAN		Established;
	UINT32		AgentId;
	ROGUE_CNF	Config;
} ROGUE_CTX, *PROGUE_CTX ;
