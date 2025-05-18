import {
	FetchJSON
} from './SAT/SAT.js'

import {
	API_STATIC_SERVER
,	SendHTML
,	SendJSONable
,	BodyAsJSON
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
client = new OAuth2Client( process.env.GOOGLE_CLIENT_ID )


const db = new Map()

const
GoogleAuth = async ( Q, S ) => {

	const
	{ credential } = await BodyAsJSON( Q )

	const
	ticket = await client.verifyIdToken(
		{	idToken		: credential
		,	audience	: process.env.GOOGLE_CLIENT_ID
		}
	)

	const payload = ticket.getPayload();
	const userId = payload.sub;

	if ( !db.has( userId ) ) db.set( userId, { id: userId, credentials: [] } )

	SendJSONable( S, { userId } )
}

const
RegisterOptions = async ( Q, S ) => {

	const
	{ userId }  = await BodyAsJSON( Q )

	const
	user = db.get( userId )

	const
	options = await generateRegistrationOptions(
		{	rpName					: 'My App'
		,	userID					: Buffer.from( user.id, 'utf8' )
		,	userName				: user.id
		,	requireUserVerification	: false
		}
	)

	user.currentChallenge = options.challenge

//	options.challenge = isoBase64URL.fromBuffer(Buffer.from(options.challenge))
//	options.user.id = isoBase64URL.fromBuffer(Buffer.from(options.user.id))

	SendJSONable( S, options )
}

const
Register = async ( Q, S ) => {

	const {
		userId
	,	attestation
	} = await BodyAsJSON( Q )

	const
	user = db.get( userId )

	const
	verification = await verifyRegistrationResponse(
		{	response			: attestation
		,	expectedChallenge	: user.currentChallenge
		,	expectedOrigin		: 'http://localhost:3000'
		,	expectedRPID		: 'localhost'
		}
	)

	if ( verification.verified ) {
		user.credentials.push( verification.registrationInfo )
		SendJSONable( S, { verified: true } )
	} else {
		S.writeHead(
			400
		,	{ 'Content-Type': type }
		)
	,	S.end( JSON.stringify( { verified: false } ) )
	}
}

import { isoBase64URL } from '@simplewebauthn/server/helpers';

/*
const
AuthOptions = async (Q, S) => {
    const { userId } = await BodyAsJSON(Q);
    const user = db.get(userId);

    const options = generateAuthenticationOptions({
        allowCredentials: user.credentials.map(cred => ({
            id: cred.credentialID, // ← Buffer
            type: 'public-key',
            transports: ['usb', 'ble', 'nfc', 'internal']
        })),
        userVerification: 'preferred',
        rpID: 'localhost'
    });

    // Base64URL encode credential IDs
    options.allowCredentials = options.allowCredentials.map(cred => ({
        ...cred,
        id: isoBase64URL.fromBuffer(cred.id)
    }));

    // Encode challenge as well
    options.challenge = isoBase64URL.fromBuffer(Buffer.from(options.challenge));

    SendJSONable(S, options);
}
*/
const
AuthOptions = async ( Q, S ) => {

	const
	{ userId }  = await BodyAsJSON( Q )

	const
	user = db.get( userId )

	const
	options = generateAuthenticationOptions(
		{	allowCredentials: user.credentials.map(
				c => (
					{	id		: c.credentialID
					,	type	: 'public-key'
					}
				)
			)
		}
	)

	user.currentChallenge = options.challenge;
	SendJSONable( S, options )
}

const
Auth = async ( Q, S ) => {

	const {
		userId
	,	attestation
	} = await BodyAsJSON( Q )

	const
	user = db.get( userId )

	const
	verification = await verifyAuthenticationResponse(
		{	response			: assertion
		,	expectedChallenge	: user.currentChallenge
		,	expectedOrigin		: 'http://localhost:3000'
		,	expectedRPID		: 'localhost'
		,	authenticator		: user.credentials[ 0 ]
		}
	)
	SendJSONable( S, { verified: verification.verified } )
}

const
server = API_STATIC_SERVER(
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
