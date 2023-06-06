# Companies 設計

## 概要

会社の管理を行う

### アクション

- 照会
- 作成
- 更新
- 削除

### 要件

- 会社は名前、郵便番号、住所、電話番号、メールアドレスを持つ
- 郵便番号と電話番号は数字のみで保存する

## モデル

- Company

| `companies` | Type   | memo               |
| ----------- | ------ | ------------------ |
| name        | String |                    |
| zip_code    | String | 1234567 format     |
| address     | String |                    |
| email       | String |                    |
| phone       | String | 09012345678 format |
