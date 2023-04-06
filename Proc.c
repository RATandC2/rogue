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

typedef struct
{
	D_API( NtQueryInformationProcess );
	D_API( NtQueryInformationToken );
	D_API( RtlSubAuthorityCountSid );
	D_API( LdrGetProcedureAddress );
	D_API( RtlInitUnicodeString );
	D_API( NtOpenProcessToken );
	D_API( RtlSubAuthoritySid );
	D_API( RtlInitAnsiString );
	D_API( LookupAccountSidA );
	D_API( NtOpenProcess );
	D_API( LdrUnloadDll );
	D_API( LdrLoadDll );
	D_API( NtClose );
} API ;

/* API Hashes */
#define H_API_NTQUERYINFORMATIONPROCESS		0x8cdc5dc2 /* NtQueryInformationProcess */
#define H_API_NTQUERYINFORMATIONTOKEN           0x0f371fe4 /* NtQueryInformationToken */
#define H_API_RTLSUBAUTHORITYCOUNTSID           0x4b23c9d3 /* RtlSubAuthoritycountSid */
#define H_API_LDRGETPROCEDUREADDRESS		0xfce76bb6 /* LdrGetProcedureAddress */
#define H_API_RTLINITUNICODESTRING		0xef52b589 /* RtlInitUnicodeString */
#define H_API_NTOPENPROCESSTOKEN                0x350dca99 /* NtOpenProcessToken */
#define H_API_RTLSUBAUTHORITYSID                0x90ed208a /* RtlSubAuthoritySid */
#define H_API_RTLINITANSISTRING			0xa0c8436d /* RtlInitAnsiString */
#define H_API_NTOPENPROCESS			0x4b82f718 /* NtOpenProcess */
#define H_API_LDRUNLOADDLL			0xd995c1e6 /* LdrUnloadDll */
#define H_API_LDRLOADDLL			0x9e456a43 /* LdrLoadDll */
#define H_API_NTCLOSE				0x40d6e69d /* NtClose */

/* LIB Hashes */
#define H_LIB_NTDLL				0x1edab0ed /* ntdll.dll */

/*!
 *
 * Purpose:
 *
 * Returns a pointer to a string representing the 
 * integrity of the target process if it is able
 * to be pulled.
 *
 * if NULL is returned, it was unable to determine
 * the process integrity.
 *
!*/
D_SEC( B ) PCHAR ProcIntegrityStr( _In_ UINT32 ProcessId )
{
        API                     Api;
        CLIENT_ID               Cid;
        OBJECT_ATTRIBUTES       Att;

        ULONG                   Len = 0;
        ULONG                   Lvl = 0;

        HANDLE                  Prc = NULL;
        HANDLE                  Tok = NULL;
        PTOKEN_MANDATORY_LABEL  Tml = NULL;

        /* Zero out stack structures */
        RtlZeroMemory( &Api, sizeof( Api ) );
        RtlZeroMemory( &Cid, sizeof( Cid ) );
        RtlZeroMemory( &Att, sizeof( Att ) );

        Api.NtQueryInformationToken  = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYINFORMATIONTOKEN ) );
        Api.RtlSubAuthorityCountSid  = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLSUBAUTHORITYCOUNTSID ) );
        Api.NtOpenProcessToken       = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTOPENPROCESSTOKEN ) );
        Api.RtlSubAuthoritySid       = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLSUBAUTHORITYSID ) );
        Api.NtOpenProcess            = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTOPENPROCESS ) );
        Api.NtClose                  = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCLOSE ) );

        Cid.UniqueProcess = C_PTR( ProcessId );
        InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

	/* Open the target process */
        if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_QUERY_LIMITED_INFORMATION, &Att, &Cid ) ) ) {
		/* Open the process token */	
                if ( NT_SUCCESS( Api.NtOpenProcessToken( Prc, TOKEN_QUERY, &Tok ) ) ) {
			/* Query the integrity Level */
                        if ( ! NT_SUCCESS( Api.NtQueryInformationToken( Tok, TokenIntegrityLevel, NULL, 0, &Len ) ) ) {
                                if ( ( Tml = MemoryAlloc( Len ) ) != NULL ) {
                                        if ( NT_SUCCESS( Api.NtQueryInformationToken( Tok, TokenIntegrityLevel, Tml, Len, &Len ) ) ) {
						/* Get the level and sub string ! */
                                                Lvl = *Api.RtlSubAuthoritySid( Tml->Label.Sid, ( *Api.RtlSubAuthorityCountSid( Tml->Label.Sid ) - 1 ) );

                                                switch( Lvl ) {
                                                        case SECURITY_MANDATORY_UNTRUSTED_RID:
                                                                return C_PTR( G_PTR( "Untrusted" ) );
                                                        case SECURITY_MANDATORY_LOW_RID:
                                                                return C_PTR( G_PTR( "Low" ) );
                                                        case SECURITY_MANDATORY_MEDIUM_RID:
                                                                return C_PTR( G_PTR( "Medium" ) );
                                                        case SECURITY_MANDATORY_HIGH_RID:
                                                                return C_PTR( G_PTR( "High" ) );
                                                        case SECURITY_MANDATORY_SYSTEM_RID:
                                                                return C_PTR( G_PTR( "System" ) );
                                                        case SECURITY_MANDATORY_PROTECTED_PROCESS_RID:
                                                                return C_PTR( G_PTR( "Protected Process" ) );
                                                }
                                        };
                                        /* Free the memory */
                                        MemoryFree( Tml );
                                };
                        };
                        /* Close the reference */
                        Api.NtClose( Tok );
                };
                /* Close the reference */
                Api.NtClose( Prc );
        };

        /* Zero out stack structures */
        RtlZeroMemory( &Api, sizeof( Api ) );
        RtlZeroMemory( &Cid, sizeof( Cid ) );
        RtlZeroMemory( &Att, sizeof( Att ) );

        return NULL;
};

/*!
 *
 * Purpose:
 *
 * Returns a pointer to a string representing the 
 * architecture of the target process if it is 
 * able to be pulled.
 *
 * If NULL is returned, it was unable to determine
 * the process architecture.
 *
!*/
D_SEC( B ) PCHAR ProcArchStr( _In_ UINT32 ProcessId )
{
	API			Api;
	CLIENT_ID		Cid;
	OBJECT_ATTRIBUTES	Att;

	PCHAR			Str = NULL;
	LPVOID			Wow = NULL;
	HANDLE			Prc = NULL;

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Cid, sizeof( Cid ) );
	RtlZeroMemory( &Att, sizeof( Att ) );

	Api.NtQueryInformationProcess = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYINFORMATIONPROCESS ) );
	Api.NtOpenProcess             = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTOPENPROCESS ) );
	Api.NtClose                   = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCLOSE ) );

	Cid.UniqueProcess = C_PTR( ProcessId );
	InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

	/* Opens the remote process */
	if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_QUERY_LIMITED_INFORMATION, &Att, &Cid ) ) ) {
		/* Query the process information */
		if ( NT_SUCCESS( Api.NtQueryInformationProcess( Prc, ProcessWow64Information, &Wow, sizeof( Wow ), NULL ) ) ) {
			/* Get the process architecture string */
			Str = Wow != NULL ? C_PTR( G_PTR( "x86" ) ) : C_PTR( G_PTR( "x64" ) );
		};
		/* Close the reference */
		Api.NtClose( Prc );
	};

	/* Zero out stack structures */
	RtlZeroMemory( &Api, sizeof( Api ) );
	RtlZeroMemory( &Cid, sizeof( Cid ) );
	RtlZeroMemory( &Att, sizeof( Att ) );

	/* Return value */
	return C_PTR( Str );
};

/*!
 *
 * Purpose:
 *
 * Returns a string representing the username for
 * the current process. if NULL is returned, it
 * means it could not pull the username from the
 * token.
 *
 * Result must be freed from memory.
 *
!*/
D_SEC( B ) BOOL ProcUserStr( _In_ UINT32 ProcessId, _Out_ PCHAR* Username, _Out_ PCHAR* WgDomain )
{
	API			Api;
	CLIENT_ID		Cid;
	ANSI_STRING		Ani;
	UNICODE_STRING		Uni;
	OBJECT_ATTRIBUTES	Att;

	UINT32			DLn = 0;
	UINT32			ULn = 0;
	UINT32			Len = 0;
	SID_NAME_USE		Snu = 0;
	BOOLEAN			Ret = FALSE;

	PCHAR			Ust = NULL;
	PCHAR			Dst = NULL;
	PVOID			Adv = NULL;
	HANDLE			Prc = NULL;
	HANDLE			Tok = NULL;
	PTOKEN_USER		Usr = NULL;

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	Api.NtQueryInformationToken = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTQUERYINFORMATIONTOKEN ) );
	Api.LdrGetProcedureAddress  = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_LDRGETPROCEDUREADDRESS ) );
	Api.RtlInitUnicodeString    = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLINITUNICODESTRING ) );
	Api.NtOpenProcessToken      = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTOPENPROCESSTOKEN ) );
	Api.RtlInitAnsiString       = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_RTLINITANSISTRING ) );
	Api.NtOpenProcess           = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTOPENPROCESS ) );
	Api.LdrUnloadDll            = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_LDRUNLOADDLL ) );
	Api.LdrLoadDll              = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_LDRLOADDLL ) );
	Api.NtClose                 = PeGetFuncEat( PebGetModule( E_HSH( H_LIB_NTDLL ) ), E_HSH( H_API_NTCLOSE ) );

	/* Load advapi32.dll */
	Api.RtlInitUnicodeString( &Uni, C_PTR( G_PTR( L"advapi32.dll" ) ) );
	
	if ( NT_SUCCESS( Api.LdrLoadDll( NULL, 0, &Uni, &Adv ) ) ) {
		Api.RtlInitAnsiString( &Ani, C_PTR( G_PTR( "LookupAccountSidA" ) ) );
		
		/* Get address of LookupAccountSidA */
		if ( NT_SUCCESS( Api.LdrGetProcedureAddress( Adv, &Ani, 0, &Api.LookupAccountSidA ) ) ) {

			/* Open the remote process */
			Cid.UniqueProcess = C_PTR( ProcessId );
			InitializeObjectAttributes( &Att, NULL, 0, NULL, NULL );

			if ( NT_SUCCESS( Api.NtOpenProcess( &Prc, PROCESS_QUERY_INFORMATION, &Att, &Cid ) ) ) {

				/* Open the process token */
				if ( NT_SUCCESS( Api.NtOpenProcessToken( Prc, TOKEN_QUERY, &Tok ) ) ) {

					/* Query information about the current token for the length */
					if ( ! NT_SUCCESS( Api.NtQueryInformationToken( Tok, TokenUser, NULL, 0, &Len ) ) ) {

						/* Allocate the block */
						if ( ( Usr = MemoryAlloc( Len ) ) != NULL ) {

							/* Query information about the current token */
							if ( NT_SUCCESS( Api.NtQueryInformationToken( Tok, TokenUser, Usr, Len, &Len ) ) ) {
								
								/* Get the length of the Username and Domain buffers */
								if ( ! Api.LookupAccountSidA( NULL, Usr->User.Sid, NULL, &ULn, NULL, &DLn, &Snu ) ) {
									/* Allocate the domain */
									if ( ( Dst = MemoryAlloc( DLn + 1 ) ) != NULL ) {
										/* Allocate the buffer */
										if ( ( Ust = MemoryAlloc( ULn + 1 ) ) != NULL ) {

											/* Get the username and domain */
											if ( Api.LookupAccountSid( NULL, Usr->User.Sid, Ust, &ULn, Dst, &DLn, &Snu ) ) {
												/* Set username and domain pointers */
												*Username = C_PTR( Ust );
												*WgDomain = C_PTR( Dst );

												/* Status */
												Ret = TRUE;
											};

											if ( Ret != TRUE ) {
												MemoryFree( Ust );
											};
										};
										if ( Ret != TRUE ) {
											MemoryFree( Dst );
										};
									};
								};
							};

							MemoryFree( Usr );
						};
					};
					Api.NtClose( Tok );
				};
				Api.NtClose( Prc );
			};
		};
		Api.LdrUnloadDll( Adv );
	};

	/* Zero out stack structures */
	RtlSecureZeroMemory( &Api, sizeof( Api ) );
	RtlSecureZeroMemory( &Cid, sizeof( Cid ) );
	RtlSecureZeroMemory( &Ani, sizeof( Ani ) );
	RtlSecureZeroMemory( &Uni, sizeof( Uni ) );
	RtlSecureZeroMemory( &Att, sizeof( Att ) );

	return Ret;
};
