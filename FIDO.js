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
} from 'fs/promises'

import {
	existsSync
,	readFileSync
,	writeFileSync
} from 'fs'


const SESSION_FILE = './sessionDB.bin'
const USER_FILE = './userDB.bin'

const	//	sessionID: { userID, challenge = null }
sessionDB = existsSync( SESSION_FILE )
?	deserialize( readFileSync( SESSION_FILE ) )
:	{}

const	//	userID: { payload, credential = [] }
userDB = existsSync( USER_FILE )
?	deserialize( readFileSync( USER_FILE ) )
:	{}

process.on(
	'SIGINT'
,	async () => (
		console.log( 'SIGINT:', sessionDB, userDB )
	,	writeFileSync( SESSION_FILE	, serialize( sessionDB	) )
	,	writeFileSync( USER_FILE	, serialize( userDB		) )
	,	process.exit( 0 )
	)
)

//	ON DEBUG
if(	!process.env.GOOGLE_CLIENT_ID	) throw 'GOOGLE_CLIENT_ID'
if(	!process.env.RPID				) throw 'RPID'
if(	!process.env.ORIGIN				) throw 'ORIGIN'
//

const
GoogleAuth = ( Q, S ) => BodyAsJSON( Q ).then(
	body => new OAuth2Client( process.env.GOOGLE_CLIENT_ID ).verifyIdToken(
		{	idToken		: body.credential
		,	audience	: process.env.GOOGLE_CLIENT_ID
		}
	).then(
		ticket => {
			const
			sessionID = crypto.randomUUID()

			const
			payload = ticket.getPayload()

			const
			userID = payload.sub

			userDB[ userID ]
			?	userDB[ userID ].payload = payload
			:	userDB[ userID ] = { payload, credentials: [] }

			sessionDB[ sessionID ] = { userID, challenge: null }

console.log( 'GoogleAuth:', sessionDB, userDB )

			S.setHeader(
				'Set-Cookie'
			,	SerializeSessionCookie( sessionID )
			)
			SendJSONable( S, payload )
		}
	).catch( _ => _401( S ) )
).catch( _ => _500( S ) )

////////////////////////////////////////////////////////////////

const
Session = Q => new Promise(
	( R, J ) => {
		const
		session = sessionDB[ ParseSessionCookie( Q.headers.cookie ) ]
		if ( !session ) throw new Error( 'Session not found' )

		const
		user = userDB[ session.userID ]
		if ( !user ) throw new Error( 'User not found' )

		R( { session, user } )
	}
)

////	TODO: DETECT ILLEGAL ATTEMPT AND REPORT IT
const
Unauthorized = ( _, Q, S ) => (
	console.error( _ )
,	_401( S, _.message )
)

const
InternalServerError = ( _, Q, S ) => (
	console.error( _ )
,	_500( S, _.message )
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
	).catch( _ => InternalServerError( _, Q, S ) )
).catch( _ => Unauthorized( _, Q, S ) )

const
Registration = ( Q, S ) => Promise.all(
	[	Session( Q )
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
		,	session.challenge = null
		,	SendJSONable( S, verified )
		)
		/*
		( { verified, registrationInfo } ) => (
			verified && (
				user.credentials.find( cred => cred.id === registrationInfo.credential.id )
				?	console.error( 'DUPPED:', cred.id )
				: (	user.credentials.push(
						{	id			: registrationInfo.credential.id
						,	publicKey	: registrationInfo.credential.publicKey
						,	counter		: registrationInfo.credential.counter
						,	transports	: body.response.transports || []
						}
					)
				)
			)
		,	session.challenge = null
		,	SendJSONable( S, verified )
		)
		*/
	).catch( _ => InternalServerError( _, Q, S ) )
).catch( _ => Unauthorized( _, Q, S ) )

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
	).catch( _ => InternalServerError( _, Q, S ) )
).catch( _ => Unauthorized( _, Q, S ) )

const
Authentication = ( Q, S ) => Promise.all(
	[	Session( Q )
	,	BodyAsJSON( Q )
	]
).then(
	( [ { session, user }, body ] ) => new Promise(
		( R, J ) => {
			const
			credential = user.credentials.find( _ => _.id === body.id )
			credential ? R( credential ) : J()
		}
	).then(
		credential => verifyAuthenticationResponse(
			{	response				: body
			,	expectedChallenge		: session.challenge
			,	expectedOrigin			: process.env.ORIGIN
			,	expectedRPID			: process.env.RPID
			,	credential				: credential
			,	requireUserVerification	: true
			}
		).then(
			( { verified, authenticationInfo } ) => (
				verified && ( credential.counter = authenticationInfo.newCounter )
			,	session.challenge = null
			,	SendJSONable( S, verified )
			)
		).catch( _ => InternalServerError( _, Q, S ) )
	).catch( _ => InternalServerError( _, Q, S ) )
).catch( _ => Unauthorized( _, Q, S ) )

const
server = CORS_API_STATIC_SERVER(
	{	'/auth/google'					: GoogleAuth
	,	'/webauthn/register-options'	: RegistrationOptions
	,	'/webauthn/register'			: Registration
	,	'/webauthn/auth-options' 		: AuthenticationOptions
	,	'/webauthn/auth'				: Authentication
	}
,	process.argv[ 2 ] || '.'
).listen(
	process.env.PORT || 3000
,	() => console.log( 'Bullet server stated on:', server.address() )
)

