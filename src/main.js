import {
	startRegistration,
	startAuthentication,
} from '@simplewebauthn/browser'

import {
	PostJSON
} from '../SAT/SAT.js'

let
userId

const
ReportError = _ => (
	console.error( _ )
,	( _ instanceof Error	) && ( STATUS.textContent = `ログイン失敗: ${ _.message }`						)
,	( _ instanceof Response	) && ( STATUS.textContent = `ログイン失敗: ${ _.status }: ${ _.statusText }`	)
)

google.accounts.id.initialize(
	{	client_id	: '1046625556668-s34tmr5ps2q2jeibg6nqvkmmpb5t92eh.apps.googleusercontent.com'
	,	auto_prompt	: true	//	trueにすると、ユーザーがログインしている場合、自動的にログインフローが開始される。
	,	callback	: response => PostJSON(
			'http://localhost:3000/auth/google'
		,	{ credential: response.credential }
		).then(
			_ => (
				userId = _.userId
			,	console.log( 'Google sign-in successful. User ID:', userId )
			,	STATUS.textContent = 'ログイン中: ' + userId
			,	ACTIONS.style.display = 'block'
			)
		).catch( ReportError )
	}
)

google.accounts.id.renderButton(
	G_SIGNIN
,	{ theme: 'outline', size: 'large', type: 'standard' }
)

google.accounts.id.prompt()

BTN_REGISTER.onclick = () => PostJSON(
	'http://localhost:3000/webauthn/register-options'
,	{ userId }
).then(
	_ => startRegistration( _ ).then(
		attestation => PostJSON(
			'http://localhost:3000/webauthn/register'
		,	{ userId, attestation }
		).then(
			_ => alert( _.verified ? '✅ 登録完了！' : '❌ 登録失敗' )
		)
	)
).catch( ReportError )

BTN_LOGIN.onclick = () => PostJSON(
	'http://localhost:3000/webauthn/auth-options'
,	{ userId }
).then(
	_ => startAuthentication( _ ).then(
		assertion => PostJSON(
			'http://localhost:3000/webauthn/auth'
		,	{ userId, assertion }
		).then(
			_ => alert( _.verified ? '✅ 認証成功！' : '❌ 認証失敗' )
		)
	)
).catch( ReportError )

