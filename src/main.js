import {
	startRegistration
,	startAuthentication
} from '@simplewebauthn/browser'

import {
	FetchJSON
,	PostJSON
} from '../SAT/SAT.js'

const
ErrorString = _ => _ instanceof Error
?	_.message
:	_ instanceof Response
	?	`${ _.status }: ${ _.statusText }`
	:	_.toString()
;

google.accounts.id.initialize(
	{	client_id	: '1046625556668-s34tmr5ps2q2jeibg6nqvkmmpb5t92eh.apps.googleusercontent.com'
	,	auto_prompt	: true	//	trueにすると、ユーザーがログインしている場合、自動的にログインフローが開始される。
	,	callback	: response => PostJSON(
			'http://localhost:3000/auth/google'
		,	response
		).then(
			payload => (
				STATUS.textContent = 'ログイン中: ' + payload.name
			,	ACTIONS.style.display = 'block'
			)
		).catch(
			_ => STATUS.textContent = `ログイン失敗: ${ErrorString( _ )}`
		)
	}
)

google.accounts.id.renderButton(
	G_SIGNIN
,	{ theme: 'outline', size: 'large', type: 'standard' }
)

google.accounts.id.prompt()

BTN_REGISTER.onclick = () => FetchJSON(
	'http://localhost:3000/webauthn/register-options'
).then(
	_ => {
		startRegistration( { optionsJSON: _ } ).then(
			_ => PostJSON(
				'http://localhost:3000/webauthn/register'
			,	_
			).then(
				_ => alert( _ ? '✅ 登録完了！' : '❌ 登録失敗' )
			)
		)
	}
).catch( _ => console.error( 'webauthn/register', ErrorString( _ ) ) )

BTN_LOGIN.onclick = () => FetchJSON(
	'http://localhost:3000/webauthn/auth-options'
).then(
	_ => startAuthentication( { optionsJSON: _ } ).then(
		_ => PostJSON(
			'http://localhost:3000/webauthn/auth'
		,	_
		).then(
			_ => alert( _ ? '✅ 認証成功！' : '❌ 認証失敗' )
		)
	)
).catch( _ => console.error( 'webauthn/auth', ErrorString( _ ) ) )

