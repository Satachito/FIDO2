import {
	FetchJSON
} from './SAT/SAT.js'

import { jwtVerify, createRemoteJWKSet } from 'jose'

const
RemoteJWKSet = createRemoteJWKSet( new URL( 'https://www.googleapis.com/oauth2/v3/certs' ) )

const
GoogleAuth = async ( Q, S ) => {

	const
	code = new URL( Q.url, `http://${Q.headers.host}` ).searchParams.get( 'code' )

	if ( !code ) throw new Error( 'No authorization_code' )

	const
	token = await FetchJSON(
		'https://oauth2.googleapis.com/token'
	,	{	method	: 'POST'
		,	headers	: { 'Content-Type': 'application/x-www-form-urlencoded' }
		,	body	: new URLSearchParams(
				{	grant_type		: 'authorization_code'
				,	client_id		: process.env.GOOGLE_CLIENT_ID
				,	client_secret	: process.env.GOOGLE_CLIENT_SECRET
				,	redirect_uri	: process.env.GOOGLE_REDIRECT_URI
				,	code
				}
			)
		}
	)

	const
	verifiedInfo = await jwtVerify(
		token.id_token
	,	RemoteJWKSet
	)

	SendHTML(
		S
	,	`ログイン成功！<br>アクセストークン: ${
			token.access_token
		}<br>IDトークン: ${
			token.id_token
		}<br>ユーザー情報: ${
			JSON.stringify( verifiedInfo )
		}`
	)
}

import {
	API_STATIC_SERVER
,	SendHTML
} from './SAT/Bullet.js'

const
server = API_STATIC_SERVER(
	{ '/auth/google': GoogleAuth }
,	process.argv[ 2 ] || '.'
).listen(
	process.env.PORT || 3000
,	() => console.log( 'Bullet server stated on:', server.address() )
)

////////////////////////////////////////////////////////////////
//	SCRAPS
////////////////////////////////////////////////////////////////

//	const
//	userInfo = await FetchJSON(
//		'https://www.googleapis.com/oauth2/v3/userinfo'
//	,	{ headers: { Authorization: `Bearer ${ token.access_token }` } }
//	)

