# Campaigns 設計

## 概要

キャンペーンの管理を行う

### アクション

- 照会
- 作成
- 更新
- 削除

### 要件

- キャンペーンは名前、コード、説明、開始日、終了日、値引きタイプ、状態を持つ
- 値引きタイプ・・・A,B,C の 3 タイプ
- 状態・・・pass:正常、fail:異常、unchecked:未チェック

#### 状態について

- 登録・更新時に状態はシステムで設定を行い、ユーザーからの入力は不要とする
- 開始日・終了日のどちらかが設定されていない、または開始日が終了日より後の場合は異常とする
- 値引きタイプが A,B,C 以外の場合は異常とする
- 異常の場合は状態を fail とする
- 画面には unchecked は表示されない

#### 開始日・終了日について

- HTML5 のカレンダーで設定ができる

## モデル

- Campaign

| `campaigns`   | Type   | memo       |
| ------------- | ------ | ---------- |
| name          | String |            |
| code          | String |            |
| description   | String | TEXT       |
| discount_type | String |            |
| status        | String |            |
| from_date     | String | YYYY-MM-DD |
| to_date       | String | YYYY-MM-DD |
