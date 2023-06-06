# Users 設計

## 概要

ユーザーの管理を行う

### アクション

- ログイン
- 照会
- 作成
- 更新
- 削除
- JWT 作成（API）
- JWT 検証（API）

### 要件

- ユーザーは名前、メールアドレス、パスワード、ロールを持つ
- ユーザーは削除できるが、削除されたら削除ユーザーとして保存される
- ロールはアドミンユーザーのみ変更可能とする
- ユーザーはアドミンユーザーを参照不可とする

### ログイン

- ユーザーはメールアドレスとパスワードでログインができる
- 開発環境ではデフォルトユーザーとデフォルトアドミンユーザーを用意する

#### デフォルトユーザー

|          | Value    |
| -------- | -------- |
| name     | user     |
| password | password |

#### デフォルトアドミンユーザー

|          | Value    |
| -------- | -------- |
| name     | admin    |
| password | password |

## モデル

- User

| `users`  | Type   | memo          |
| -------- | ------ | ------------- |
| name     | String |               |
| email    | String |               |
| password | String | Save as hash  |
| role     | String | ADMIN or USER |

- DeletedUser

| `deleted_users` | Type   | memo |
| --------------- | ------ | ---- |
| name            | String |      |
| email           | String |      |
| password        | String |      |
| role            | String |      |
