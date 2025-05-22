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

import crypto from 'crypto'

import {
	parse
,	serialize
} from 'cookie'

import { isoBase64URL } from '@simplewebauthn/server/helpers';


const
client = new OAuth2Client( process.env.GOOGLE_CLIENT_ID )


//	TODO: Make database
import { Low } from 'lowdb'
import { JSONFile } from 'lowdb/node'

const db = new Low( new JSONFile( 'Payloads.json' ), {} )
await db.read()

const
GetPayload = async sessionID => {
    await db.read()
    const $ = db.data[ sessionID ]
    if ( !$ ) throw new Error( 'No session payload' )
    return $
}

const
SetPayload = async ( sessionID, payload ) => {
    db.data[ sessionID ] = payload
    await db.write()
}

/*
  payload: {
    iss: 'https://accounts.google.com',
    azp: '1046625556668-s34tmr5ps2q2jeibg6nqvkmmpb5t92eh.apps.googleusercontent.com',
    aud: '1046625556668-s34tmr5ps2q2jeibg6nqvkmmpb5t92eh.apps.googleusercontent.com',
    sub: '106308084972031215345',
    email: 's8at2or8u@gmail.com',
    email_verified: true,
    nbf: 1747718135,
    name: 'Satoru Ogura',
    picture: 'https://lh3.googleusercontent.com/a/ACg8ocI1fqL5Icmdfch3st-tVqbaw0kM7Eht-kld9M__NRG73mqmDn4s=s96-c',
    given_name: 'Satoru',
    family_name: 'Ogura',
    iat: 1747718435,
    exp: 1747722035,
    jti: '28060b0f82c8cb6f32d6bb36717d08c8c0891be1'
  }
*/

function sign(value) {
	return crypto
		.createHmac('sha256', process.env.SESSION_SECRET)
		.update(value)
		.digest('hex')
}

function serializeSessionCookie(sessionID) {
	const signature = sign(sessionID)
	const value = `${sessionID}.${signature}`
	return serialize(
		'session',
		value,
		{ httpOnly: true, path: '/', sameSite: 'lax', secure: false, maxAge: 60 * 60 * 24 * 7 }
	)
}

function parseSessionCookie(cookieHeader) {
	const cookies = parse(cookieHeader)
	const session = cookies.session
	if (!session) throw new Error('No session cookie')

	const [sessionID, signature] = session.split('.')
	if (sign(sessionID) !== signature) throw new Error('Invalid session signature')
	return sessionID
}


const
GoogleAuth = ( Q, S ) => BodyAsJSON( Q ).then(
	body => client.verifyIdToken(
		{	idToken		: body.credential
		,	audience	: process.env.GOOGLE_CLIENT_ID
		}
	).then(
		ticket => {
			const
			sessionID = crypto.randomUUID()
			const
			payload = ticket.getPayload()
			SetPayload( sessionID, payload )
			S.setHeader(
				'Set-Cookie'
			,	serializeSessionCookie( sessionID )
			/*
			,	serialize(
					'sessionID'
				,	sessionID
				,	{	httpOnly	: true
					,	path		: '/'
					,	sameSite	: 'lax'
					,	secure		: false	// HTTPS にするなら true に
					,	maxAge		: 60 * 60 * 24 * 7 // 1 week
					}
				)
			*/
			)
			SendJSONable( S, payload )
		}
	)
)

const
SessionID = Q => new Promise( R => R( parseSessionCookie( Q.headers.cookie ) ) )

const
RegisterOptions = ( Q, S ) => SessionID( Q ).then(
	sessionID => GetPayload( sessionID ).then(
		payload => generateRegistrationOptions(
			{	rpName					: 'My App'
			,	userID					: Buffer.from( payload.sub, 'utf8' )
			,	userName				: payload.name
			,	requireUserVerification	: true
			}
		).then(
			options => (
				payload.currentChallenge = options.challenge
			,	payload.credentials = []
			,	SetPayload( sessionID, payload )
			,	SendJSONable( S, options )
			)
		)
	)
).catch(
	_ => (
		console.error( _ )
	,	S.end( 'Unauthorized' )	//	TODO:
	)
)

const
PublicKeyEncoded = _ => (
	_.publicKey = _.publicKey.toString( 'base64url' )
,	_
)

const
PublicKeyDecoded = _ => (
	_.publicKey = Buffer.from( _.publicKey, 'base64url' )
,	_
)

const
Register = ( Q, S ) => SessionID( Q ).then(
	sessionID => Promise.all(
		[	BodyAsJSON( Q )
		,	GetPayload( sessionID )
		]
	).then( 
		( [ response, payload ] ) => verifyRegistrationResponse(
			{	response
			,	expectedChallenge	: payload.currentChallenge
			,	expectedOrigin		: 'http://localhost:3000'
			,	expectedRPID		: 'localhost'
			}
		).then(
			_ => _.verified
			? (	payload.credentials.push( PublicKeyEncoded( _.registrationInfo.credential ) )
			,	db.write()
			,	SendJSONable( S, true )
			)
			:	SendJSONable( S, false )
		)
	)
).catch(
	_ => (
		console.error( _ )
	,	_500( S )
	)
)

const
AuthOptions = ( Q, S ) => SessionID( Q ).then(
	sessionID => GetPayload( sessionID ).then(
		payload => generateAuthenticationOptions(
			{	allowCredentials	: payload.credentials
			,	userVerification	: 'required'
			,	rpID				: 'localhost'
			}
		).then(
			options => (
				payload.currentChallenge = options.challenge
			,	SetPayload( sessionID, payload )
			,	SendJSONable( S, options )
			)
		)
	)
).catch(
	_ => (
		console.error( _ )
	,	_500( S )
	)
)

const
Auth = ( Q, S ) => SessionID( Q ).then(
	sessionID => Promise.all(
		[	BodyAsJSON( Q )
		,	GetPayload( sessionID )
		]
	).then(
		( [ response, payload ] ) => {
			const
			credential = PublicKeyDecoded( payload.credentials.find( c => c.id === response.id ) )

			if ( !credential ) {
				console.error( 'No matching credential found' )
				return _403( S )
			}

			const
			authenticator = {
				credentialID		: Buffer.from( credential.id, 'base64url' )
			,	credentialPublicKey	: credential.publicKey
			,	counter				: credential.counter
			,	transports			: credential.transports
			}

			console.log( authenticator )

			verifyAuthenticationResponse(
				{	response
				,	expectedChallenge	: payload.currentChallenge
				,	expectedOrigin		: 'http://localhost:3000'
				,	expectedRPID		: 'localhost'
				,	authenticator
				}
			).then(
				_ => SendJSONable( S, _.verified )
			).catch(
				_ => console.error( 'verifyAuthenticationResponse', _ )
			)
		}
	)
).catch(
	_ => (
		console.error( _ )
	,	_500( S )
	)
)

const
server = CORS_API_STATIC_SERVER(
	{	'/auth/google'					: GoogleAuth
	,	'/webauthn/register-options'	: RegisterOptions
	,	'/webauthn/register'			: Register
	,	'/webauthn/auth-options' 		: AuthOptions
	,	'/webauthn/auth'				: Auth
	}
,	process.argv[ 2 ] || '.'
).listen(
	process.env.PORT || 3000
,	() => console.log( 'Bullet server stated on:', server.address() )
)

/*
					cred => (
						{	id			: cred.credential.id
						,	type		: cred.credential.type
						,	transports	: cred.credential.transports	//	[ 'usb', 'ble', 'nfc', 'internal' ]
						}
					)
*/
