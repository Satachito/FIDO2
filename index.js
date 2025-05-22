import https from 'https'
import http from 'http'
import fs from 'fs'
import express from 'express'
import session from 'express-session'
import memoryStore from 'memorystore'

import {
	generateAuthenticationOptions
,	generateRegistrationOptions
,	verifyAuthenticationResponse
,	verifyRegistrationResponse
} from '@simplewebauthn/server'

//import { LoggedInUser } from './example-server'
//interface LoggedInUser {
//	id: string;
//	username: string;
//	credentials: WebAuthnCredential[];
//}

const
app = express ()

const
MemoryStore = memoryStore ( session )

const {
	ENABLE_CONFORMANCE
,	ENABLE_HTTPS
,	RP_ID = 'localhost'
} = process.env

app.use ( express .static ( './public/' ) )
app.use ( express .json () )
app.use (
	session (
		{	secret : 'secret123'
		,	saveUninitialized : true
		,	resave : false
		,	cookie : {
				maxAge : 86400000
			,	httpOnly : true
			}
		,	store : new MemoryStore (
				{	checkPeriod : 86_400_000
				}
			)
		}
	)
)

if ( ENABLE_CONFORMANCE === 'true' ) {
	import ( './fido-conformance' ) .then (
		(	{	fidoRouteSuffix
			,	fidoConformanceRouter
			}
		) => {
			app .use (
				fidoRouteSuffix
			,	fidoConformanceRouter
			)
		}
	)
}

export
const rpID = RP_ID
export
let expectedOrigin = ''
const
loggedInUserId = 'internalUserId'

const
inMemoryUserDB = {	//	 : { [ loggedInUserId : string ] : LoggedInUser }
	[ loggedInUserId ] : {
		id : loggedInUserId
	,	
		username : `user@${rpID}`
	,	
		credentials : []
	,	
	}
,	
}
;
app .get (
	'/generate-registration-options'
,	async ( req, res ) => {
		const
		user = inMemoryUserDB [ loggedInUserId ]

		const {
			username
		,	credentials
		} = user

		const
		opts = {	//	 : GenerateRegistrationOptionsOpts
			rpName : 'SimpleWebAuthn Example'
		,	rpID
		,	userName : username
		,	timeout : 60000
		,	attestationType : 'none'
		,	excludeCredentials : credentials.map (
				( cred ) => (
					{	id : cred.id
					,	type : 'public-key'
					,	transports : cred.transports
					}
				)
			)
		,	authenticatorSelection : {
				residentKey : 'discouraged'
			,	userVerification : 'preferred'
			}
		,	supportedAlgorithmIDs : [
				- 7
			,	- 257
			]
		}

		const
		options = await generateRegistrationOptions ( opts )

		req .session.currentChallenge = options.challenge ;
		res .send ( options )
	}
)

app .post (
	'/verify-registration'
,	async (
		req
	,	res
	) => {
		const
		body = req.body	//	RegistrationResponseJSON
		const
		user = inMemoryUserDB [ loggedInUserId ]
		const
		expectedChallenge = req.session.currentChallenge
		let
		verification	//	VerifiedRegistrationResponse
		try {
			const
			opts = {	//	VerifyRegistrationResponseOpts
				response : body
			,	
				expectedChallenge : `${expectedChallenge}`
			,	
				expectedOrigin
			,	
				expectedRPID : rpID
			,	
				requireUserVerification : false
			,	
			}
			;
			verification = await verifyRegistrationResponse ( opts )
			;
		}
		catch ( error ) {
			console.error ( error )
			return res.status ( 400 ).send ( { error : error.message } )
		}
		const {
			verified
		,	registrationInfo
		} = verification ;
		if ( verified && registrationInfo ) {
			const { credential } = registrationInfo ;
			const
			existingCredential = user.credentials.find ( ( cred ) => cred.id === credential.id )
			;
			if ( ! existingCredential ) {
				const
				newCredential = {	//	WebAuthnCredential
					id : credential.id
				,	
					publicKey : credential.publicKey
				,	
					counter : credential.counter
				,	
					transports : body.response.transports
				,	
				}
				;
				user .credentials.push ( newCredential )
				;
			}
		}
		req .session.currentChallenge = undefined ;
		res .send ( { verified } )
		;
	}
)
;
app .get (
	'/generate-authentication-options'
,	async (
		req
	,	res
	) => {
		const
		user = inMemoryUserDB [ loggedInUserId ]
		;
		const
		opts = {	//	GenerateAuthenticationOptionsOpts
			timeout : 60000
		,	
			allowCredentials : user.credentials.map (
				( cred ) => (
					{	id : cred.id
					,	
						type : 'public-key'
					,	
						transports : cred.transports
					,	
					}
				)
			)
		,	
			userVerification : 'preferred'
		,	
			rpID
		,	
		}
		;
		const
		options = await generateAuthenticationOptions ( opts )
		;
		req .session.currentChallenge = options.challenge ;
		res .send ( options )
		;
	}
)
;
app .post (
	'/verify-authentication'
,	async (
		req
	,	res
	) => {
		const
		body = req.body	//	AuthenticationResponseJSON
		const
		user = inMemoryUserDB [ loggedInUserId ]
		;
		const
		expectedChallenge = req.session.currentChallenge ;
		let
		dbCredential	//	WebAuthnCredential | undefined
		for (
			const
			cred
			of
			user .credentials
		) { if ( cred .id === body.id ) { dbCredential = cred ; break ; } }
		if ( ! dbCredential ) {
			return
			res .status ( 400 ) .send (
				{	error : 'Authenticator is not registered with this site'
				,	
				}
			)
			;
		}
		let
		verification	//	VerifiedAuthenticationResponse
		try {
			const
			opts = {	//	VerifyAuthenticationResponseOpts
				response : body
			,	
				expectedChallenge : `${expectedChallenge}`
			,	
				expectedOrigin
			,	
				expectedRPID : rpID
			,	
				credential : dbCredential
			,	
				requireUserVerification : false
			,	
			}
			;
			verification = await verifyAuthenticationResponse ( opts )
			;
		}
		catch ( error ) {
			console.error ( error )
			return res.status( 400 ).send ( { error : error.message } )
		}
		const {
			verified
		,	authenticationInfo
		} = verification ;
		if ( verified ) { dbCredential .counter = authenticationInfo.newCounter ; }
		req .session.currentChallenge = undefined ;
		res .send ( { verified } )
		;
	}
)
;
if ( ENABLE_HTTPS ) {
	const
	host = '0.0.0.0' ;
	const
	port = 443 ;
	expectedOrigin = `https://${rpID}` ;
	https .createServer (
		{	key : fs.readFileSync ( `./${rpID}.key` )
		,	
			cert : fs.readFileSync ( `./${rpID}.crt` )
		,	
		}
	,	
		app
	,	
	)
	.listen (
		port
	,	host
	,	 () => {
			console .log ( `🚀 Server ready at ${expectedOrigin} (${host}:${port})` )
			;
		}
	)
	;
}
else {
	const
	host = '127.0.0.1' ;
	const
	port = 8000 ;
	expectedOrigin = `http://localhost:${port}` ;
	http .createServer ( app ) .listen (
		port
	,	host
	,	 () => {
			console .log ( `🚀 Server ready at ${expectedOrigin} (${host}:${port})` )
			;
		}
	)
	;
}

