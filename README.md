



















/*
以下に、`@simplewebauthn/server` の主なルーチン（`verifyRegistrationResponse`, `verifyAuthenticationResponse`）で発生し得る **エラー名 (`err.name`) と意味・対処法** のマトリクスを示します：

---

### ✅ SimpleWebAuthn のエラーマトリクス一覧

| `err.name`          | 典型的な原因                                               | ユーザーへの説明             | 対処（HTTP ステータス）                       |
| ------------------- | ---------------------------------------------------- | -------------------- | ------------------------------------ |
| `InvalidStateError` | 同じ認証器がすでに登録されている                                     | 「すでに登録済みの認証器です」      | `400 Bad Request` (`_400`)           |
| `TypeError`         | クライアントから送られた JSON の構造に問題あり、または undefined 値など         | 「データ形式が正しくありません」     | `400 Bad Request` (`_400`)           |
| `SecurityError`     | Origin, RPID が一致しない／攻撃と見なされる入力                       | 「セキュリティポリシーに違反しています」 | `400 Bad Request` (`_400`)           |
| `NotAllowedError`   | ユーザーが登録／認証をキャンセルした、またはタイムアウト                         | 「操作がキャンセルされました」      | `401 Unauthorized` (`_401`)          |
| `ConstraintError`   | 認証器が選択条件を満たさない（e.g., `residentKey: required` なのに非対応） | 「対応していない認証器です」       | `400 Bad Request` (`_400`)           |
| `UnknownError`      | 内部的に何か不明な原因で失敗                                       | 「不明なエラーが発生しました」      | `500 Internal Server Error` (`_500`) |
| `AbortError`        | ユーザーが操作を中止した                                         | 「認証操作が中断されました」       | `401 Unauthorized` (`_401`)          |
| `DOMException`      | 上記と類似、WebAuthn レベルでキャンセルや中断などが発生                     | 「ブラウザ側で操作が中断されました」   | `401 Unauthorized` (`_401`)          |

---

### 🛠 実装での使い方（例）

```js
.catch(err => {
  console.error('WebAuthn error:', err.name, err.message);

  switch (err.name) {
    case 'InvalidStateError':
      return _400(S, 'その認証器はすでに登録されています');
    case 'TypeError':
    case 'SecurityError':
    case 'ConstraintError':
      return _400(S, err.message);
    case 'NotAllowedError':
    case 'AbortError':
    case 'DOMException':
      return _401(S, 'ユーザーが操作をキャンセルしました');
    case 'UnknownError':
    default:
      return _500(S);
  }
});
```

---

### 💡補足

* クライアントから `startRegistration()` や `startAuthentication()` が返す Promise の中でも同じような `err.name` が出ます。
* `@simplewebauthn/browser` を使っていれば、クライアントでも `error.name` を使ってフィードバックを改善できます。

---

もっと詳細なケース（e.g., FIDO2 error code, CTAP error code に紐づけるなど）が必要であれば、お気軽にどうぞ。
*/
