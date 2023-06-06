# Products 設計

## 概要

商品の管理を行う

### アクション

- 一覧（検索）
- 照会
- 作成
- 更新
- 削除

### 要件

- 商品はショップ ID、名前、コード、重さ、高さ、値段、税率タイプを持つ
- 商品管理の各画面へはショップを選択している状態で遷移する
- 税率タイプは、税率、税込みかどうか、端数処理方法を持つ
- 入力者は、税率、税込みかどうか、端数処理方法をそれぞれを選択する
- 商品登録・編集時にカテゴリとの紐付けを行う
- 商品検索の項目
  - 名前：部分一致検索、大文字小文字を区別しない
  - コード：部分一致検索、大文字小文字を区別しない
  - カテゴリ：チェックボックスによる複数選択
  - 重さ：範囲検索
  - 高さ：範囲検索
  - 金額：範囲検索

## モデル

- Product

| `products` | Type    | Required | memo    |
| ---------- | ------- | :------: | ------- |
| shop_id    | Integer |    ○     |         |
| name       | String  |    ○     |         |
| code       | String  |    ○     |         |
| weight     | Integer |    ○     |         |
| height     | Integer |    ○     |         |
| price      | Double  |    ○     |         |
| tax_type   | Integer |    ○     | TaxType |

## 定数

TODO: データベース化

- TaxType

| ID  | Rate(%) | Tax included | Rounding |
| --- | ------- | ------------ | -------- |
| 1   | 0       | No           | Floor    |
| 2   | 0       | No           | Round    |
| 3   | 0       | No           | Ceil     |
| 4   | 0       | Yes          | Floor    |
| 5   | 0       | Yes          | Round    |
| 6   | 0       | Yes          | Ceil     |
| 7   | 8       | No           | Floor    |
| 8   | 8       | No           | Round    |
| 9   | 8       | No           | Ceil     |
| 10  | 8       | Yes          | Floor    |
| 11  | 8       | Yes          | Round    |
| 12  | 8       | Yes          | Ceil     |
| 13  | 10      | No           | Floor    |
| 14  | 10      | No           | Round    |
| 15  | 10      | No           | Ceil     |
| 16  | 10      | Yes          | Floor    |
| 17  | 10      | Yes          | Round    |
| 18  | 10      | Yes          | Ceil     |
