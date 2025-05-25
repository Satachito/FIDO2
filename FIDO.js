import {
	FetchJSON
} from './SAT/SAT.js'

import {
	API_STATIC_SERVER
,	CORS_API_STATIC_SERVER
,	SendJSONable
,	BodyAsJSON
,	_400
,	_401
,	_403
,	_404
,	_500
,	SerializeSessionCookie
,	ParseSessionCookie
} from './SAT/Bullet.js'

import {
	generateRegistrationOptions
,	verifyRegistrationResponse
,	generateAuthenticationOptions
,	verifyAuthenticationResponse
} from '@simplewebauthn/server'

import {
	isoUint8Array
,	isoBase64URL
} from '@simplewebauthn/server/helpers'


import {
	OAuth2Client
} from 'google-auth-library'

import {
	serialize
,	deserialize
} from 'v8'

import {
	existsSync
} from 'fs'

import {
	readFile
,	writeFile
} from 'fs/promises'


const SESSION_FILE = './sessionDB.bin'
const USER_FILE = './userDB.bin'

const	//	sessionID: { userID, challenge = null }
sessionDB = existsSync( SESSION_FILE )
?	deserialize( await readFile( SESSION_FILE ) )
:	{}

const	//	userID: { payload, credential = [] }
userDB = existsSync( USER_FILE )
?	deserialize( await readFile( USER_FILE ) )
:	{}

const
SyncDBs = async () => (
	await writeFile( SESSION_FILE	, serialize( sessionDB	) )
,	await writeFile( USER_FILE		, serialize( userDB		) )
)

process.on(
	'SIGINT'
,	async () => (
		console.log( 'SIGINT:', sessionDB, userDB )
	,	await SyncDBs()
	,	process.exit( 0 )
	)
)

//	ON DEBUG
if(	!process.env.GOOGLE_CLIENT_ID	) throw 'NO evn.GOOGLE_CLIENT_ID'
if(	!process.env.RPID				) throw 'NO evn.RPID'
if(	!process.env.ORIGIN				) throw 'NO evn.ORIGIN'
if(	!process.env.SESSION_SECRET		) throw 'NO evn.SESSION_SECRET'
if(	process.env.SESSION_SECRET.length < 32
||	!/^[a-zA-Z0-9!@#$%^&*()_+=-]{32,}$/.test( process.env.SESSION_SECRET )
) throw 'env.SESSION_SECRET TOO WEAK'
//

const
Unauthorized = ( E, Q, S ) => (
	console.error( E )
,	_401( S, E.message )
)

const
InternalServerError = ( _, Q, S ) => (
	console.error( _ )
,	_500( S, `${_}` )
)

const
GoogleAuth = ( Q, S ) => BodyAsJSON( Q ).then(
	//	idToken が nullable の場合、TypeErrorで下のcatchで処理される
	body => new OAuth2Client( process.env.GOOGLE_CLIENT_ID ).verifyIdToken(
		{	idToken		: body.credential
		,	audience	: process.env.GOOGLE_CLIENT_ID
		}
	).then(
		async ticket => {
			const
			sessionID = crypto.randomUUID()

			const
			payload = ticket.getPayload()

			if ( !payload || !payload.sub ) throw new Error( 'Google payload is missing or invalid.' )

			const
			userID = payload.sub

			userDB[ userID ]
			?	userDB[ userID ].payload = payload
			:	userDB[ userID ] = { payload, credentials: [] }

			sessionDB[ sessionID ] = { userID, challenge: null }

console.log( 'GoogleAuth:', sessionDB, userDB )
			await SyncDBs()

			S.setHeader(
				'Set-Cookie'
			,	SerializeSessionCookie( sessionID )
			)
			SendJSONable( S, payload )
		}
	).catch( E => Unauthorized( E, Q, S ) )		//	verifyIdToken
).catch( _ => InternalServerError( _, Q, S ) )	//	BodyAsJSON

////////////////////////////////////////////////////////////////

const
CatchSWA = ( _, Q, S ) => {

	const
	$ = _ instanceof Error ? `${_.name}:${_.message}` : `${_}`

	console.error( 'CatchSWA:', $ )

	if ( _ instanceof Error ) {

		switch ( _.name ) {

		case 'InvalidStateError':
		case 'TypeError':
		case 'SecurityError':
		case 'ConstraintError':
			_400( S, $ )
			break

		case 'NotAllowedError':
		case 'AbortError':
		case 'DOMException':
			_401( S, $ )
			break

		default:
			_500( S, $ )
			break
		}
	} else {
		_500( S, $ )
	}
}

const
Session = ( Q, checkChallenge = false ) => new Promise(
	( R, J ) => {
		const
		sessionID = ParseSessionCookie( Q.headers.cookie )
		if ( !sessionID ) throw new Error( 'Invalid session' )

		const
		session = sessionDB[ sessionID ]
		if ( !session ) throw new Error( 'Session not found' )

		if ( checkChallenge && !session.challenge ) throw new Error( 'No challenge' )

		const
		user = userDB[ session.userID ]
		if ( !user ) throw new Error( 'User not found' )

		R( { session, user } )
	}
)

const
RegistrationOptions = ( Q, S ) => Session( Q ).then(
	( { session, user } ) => generateRegistrationOptions(
		{	//	GenerateRegistrationOptionsOpts
			rpName					: 'SAT AUTH'
		,	rpID					: process.env.RPID
		,	userID					: isoUint8Array.fromUTF8String( session.userID )
		,	userName				: user.payload.name
		,	userDisplayName			: user.payload.displayName

		,	timeout					: 60000
		,	attestationType			: 'none'				//	none, indirect, direct, enterprise, ...etc
		,	authenticatorSelection	: {						//	Passkey -> residentKey: 'required' + userVerification: 'required'
				residentKey				: 'required'
			,	userVerification		: 'required'
		//	,	authenticatorAttachment	: 'platform'		//	そのデバイスでのみの対応になる->スマホでの認証とかができなくなる。
			}
		,	excludeCredentials		: user.credentials.map(	//	二重登録防止
				cred => (
					{	id				: isoBase64URL.fromBuffer( cred.id )
					,	type			: 'public-key'
					,	transports		: cred.transports
					}
				)
			)
		,	supportedAlgorithmIDs	: [
				- 7		//	ES256
			,	- 257	//	RS256
			]
		//	extension
		}
	).then(
		options => (
			session.challenge = options.challenge
		,	SendJSONable( S, options )
		)
	).catch( _ => CatchSWA( _, Q, S ) )	//	generateRegistrationOptions
).catch( E => Unauthorized( E, Q, S ) )	//	Session

const
Registration = ( Q, S ) => Promise.all(
	[	Session( Q, true )
	,	BodyAsJSON( Q )
	]
).then(
	( [ { session, user }, body ] ) => verifyRegistrationResponse(
		{	response				: body
		,	expectedChallenge		: session.challenge
		,	expectedOrigin			: process.env.ORIGIN
		,	expectedRPID			: process.env.RPID
		,	requireUserVerification	: true
		}
	).then(
		( { verified, registrationInfo } ) => (
			verified && user.credentials.push(
				{	id			: registrationInfo.credential.id
				,	publicKey	: registrationInfo.credential.publicKey
				,	counter		: registrationInfo.credential.counter
				,	transports	: body.response.transports || []
				}
			)
		,	SendJSONable( S, verified )
		)
	).catch( _ => CatchSWA( _, Q, S ) ).finally(	//	verifyRegistrationResponse
		() => session.challenge = null
	)
).catch( E => Unauthorized( E, Q, S ) )				//	[ Session, BodyAsJSON ]

const
AuthenticationOptions = ( Q, S ) => Session( Q ).then(
	( { session, user } ) => generateAuthenticationOptions(
		{	timeout				: 60000
		,	allowCredentials	: user.credentials.map (
				cred => (
					{	id			: cred.id
					,	type		: 'public-key'
					,	transports	: cred.transports
					}
				)
			)
		,	userVerification	: 'required'
		,	rpID				: process.env.RPID
		}
	).then(
		options => (
			session.challenge = options.challenge
		,	SendJSONable( S, options )
		)
	).catch( _ => CatchSWA( _, Q, S ) )	//	generateAuthenticationOptions
).catch( E => Unauthorized( E, Q, S ) )	//	Session

const
Authentication = ( Q, S ) => Promise.all(
	[	Session( Q, true )
	,	BodyAsJSON( Q )
	]
).then(
	( [ { session, user }, body ] ) => new Promise(
		( R, J ) => {
			const
			credential = user.credentials.find(
				_ => Buffer.compare( Buffer.from( _.id ), Buffer.from( body.id ) ) === 0
			)
			credential ? R( credential ) : J()
		}
	).then(
		credential => verifyAuthenticationResponse(
			{	response				: body
			,	expectedChallenge		: session.challenge
			,	expectedOrigin			: process.env.ORIGIN
			,	expectedRPID			: process.env.RPID
			,	credential
			,	requireUserVerification	: true
			}
		).then(
			( { verified, authenticationInfo } ) => (
				verified && ( credential.counter = authenticationInfo.newCounter )
			,	SendJSONable( S, verified )
			)
		).catch( _ => CatchSWA( _, Q, S ) ).finally(	//	verifyAuthenticationResponse
			() => session.challenge = null
		)
	).catch( _ => InternalServerError( _, Q, S ) )		//	credential が取れなかった場合
).catch( E => Unauthorized( E, Q, S ) )					//	[ Session, BodyAsJSON ]



const
server = CORS_API_STATIC_SERVER(
	{	'/auth/google'					: GoogleAuth
	,	'/webauthn/register-options'	: RegistrationOptions
	,	'/webauthn/register'			: Registration
	,	'/webauthn/auth-options' 		: AuthenticationOptions
	,	'/webauthn/auth'				: Authentication
	}
,	process.argv[ 2 ] || '.'
,	origin => [ 'http://localhost:3000' ].includes( origin )
).listen(
	process.env.PORT || 3000
,	() => console.log( 'Bullet server stated on:', server.address() )
)
