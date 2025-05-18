import {
	startRegistration,
	startAuthentication,
} from '@simplewebauthn/browser'

// Google Sign-In APIの初期化とコールバック関数を定義
function initializeGoogleSignIn() {
	google.accounts.id.initialize({
		client_id: '1046625556668-s34tmr5ps2q2jeibg6nqvkmmpb5t92eh.apps.googleusercontent.com',
		callback: handleCredentialResponse, // コールバック関数を直接設定
		auto_prompt: false,
	});
	google.accounts.id.renderButton( //buttonのrender
		document.querySelector(".g_id_signin"),
		{ theme: "outline", size: "large" }  // customization attributes
	);
	//auto_promptをtrueにすると、ユーザーがログインしている場合、自動的にログインフローが開始されます。
	//今回は、ボタンをクリックしたときにログインフローを開始するようにするため、auto_promptをfalseに設定
	google.accounts.id.prompt(); // ユーザーにログインを促す
}


let userId = null;

// Googleログイン後の処理
async function handleCredentialResponse(response) {
	try {
		const res = await fetch('http://localhost:3000/auth/google', {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify({ credential: response.credential }),
		});
		const data = await res.json();
		if (!res.ok) {
			throw new Error(`HTTP error! status: ${res.status}, message: ${data.message || 'Failed to authenticate with Google'}`);
		}
		userId = data.userId;
		console.log('Google sign-in successful. User ID:', userId); // ログを追加
		document.getElementById('status').textContent = `ログイン中: ${userId}`;
		document.getElementById('actions').style.display = 'block';
	} catch (error) {
		console.error('Error handling Google credential response:', error);
		document.getElementById('status').textContent = `ログイン失敗: ${error.message}`; //エラーメッセージ表示
	}
}



// WebAuthn登録処理
document.addEventListener('DOMContentLoaded', () => { //DOMContentLoadedで初期化
	initializeGoogleSignIn(); //googleログイン初期化

	document.getElementById('btn-register').onclick = async () => {
		try {
			const options = await (await fetch('http://localhost:3000/webauthn/register-options', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ userId }),
			})).json();

			const attestation = await startRegistration(options);

			const res = await fetch('http://localhost:3000/webauthn/register', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ userId, attestation }),
			});

			const responseData = await res.json();
			if (!res.ok) {
				 throw new Error(`HTTP error! status: ${res.status}, message: ${responseData.message || 'WebAuthn registration failed'}`);
			}
			alert(responseData.verified ? '✅ 登録完了！' : '❌ 登録失敗');
		} catch (error) {
			console.error('Error during WebAuthn registration:', error);
			alert('❌ 登録中にエラーが発生しました。');
		}
	};

	// WebAuthnログイン処理
	document.getElementById('btn-login').onclick = async () => {
		try {
			const options = await (await fetch('http://localhost:3000/webauthn/auth-options', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ userId }),
			})).json();

			const assertion = await startAuthentication(options);

			const res = await fetch('http://localhost:3000/webauthn/auth', {
				method: 'POST',
				headers: { 'Content-Type': 'application/json' },
				body: JSON.stringify({ userId, assertion }),
			});
			const responseData = await res.json();
			if (!res.ok) {
				throw new Error(`HTTP error! status: ${res.status}, message: ${responseData.message || 'WebAuthn authentication failed'}`);
			}
			alert(responseData.verified ? '✅ 認証成功！' : '❌ 認証失敗');
		} catch (error) {
			console.error('Error during WebAuthn authentication:', error);
			alert('❌ 認証中にエラーが発生しました。');
		}
	};
});
