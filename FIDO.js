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
	OAuth2Client
} from 'google-auth-library'

const
sessionDB = {	//	sessionID: { userID, challenge = null }
}

const
userDB = {		//	userID: { payload, credential = [] }
}

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
		if ( !session ) return J( new Error( 'Session not found' ) )

		const
		user = userDB[ session.userID ]
		if ( !user ) return J( new Error( 'User not found' ) )

		R( { session, user } )
	}
)

////	TODO: DETECT ILLEGAL ATTEMPT AND LOG IT
const
Unauthorized = ( _, Q, S ) => (
	console.error( _ )
,	_401( S )
)

const
InternalServerError = ( _, Q, S ) => (
	console.error( _ )
,	_500( S )
)

const
RegistrationOptions = ( Q, S ) => Session( Q ).then(
	( { session, user } ) => generateRegistrationOptions( 
		{	//	GenerateRegistrationOptionsOpts
			rpName					: 'SimpleWebAuthn Example'
		,	rpID					: process.env.RPID
		,	userName				: user.payload.name
		,	timeout					: 60000
		,	attestationType			: 'none'
		,	excludeCredentials		: user.credentials.map(
				cred => (
					{	id			: cred.id
					,	type		: 'public-key'
					,	transports	: cred.transports
					}
				)
			)
		,	authenticatorSelection	: {
				residentKey			: 'discouraged'
			,	userVerification	: 'preferred'
			}
		,	supportedAlgorithmIDs	: [
				- 7
			,	- 257
			]
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
		,	requireUserVerification	: false
		}
	).then(
		( { verified, registrationInfo } )=> {
			if ( verified && registrationInfo ) {
				const
				{ credential } = registrationInfo
				const
				existingCredential = user.credentials.find( cred => cred.id === credential.id )
				if ( ! existingCredential ) {
					const
					newCredential = {	//	WebAuthnCredential
						id			: credential.id
					,	publicKey	: credential.publicKey
					,	counter		: credential.counter
					,	transports	: body.response.transports
					}
					user.credentials.push ( newCredential )
				}
			}
			SendJSONable( S, verified )
		}
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
		,	userVerification	: 'preferred'
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
			,	requireUserVerification	: false
			}
		).then(
			( { verified, authenticationInfo } ) => { 
				if ( verified ) credential.counter = authenticationInfo.newCounter
				session.challenge = null;
				SendJSONable( S, verified )
			}
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

