# Orders 設計

## 概要

受注の管理を行う
入金処理と発送処理を別画面で一括で行うことができる
受注キャンセル状態には返金画面へ遷移できる

### アクション

- 照会
- 作成
- 更新
- ~~削除~~
- 入金処理
- 発送処理

### 要件

- 受注は購入者 ID、補足メモ、購入金額関連、ステータス、支払い額、支払いステータス、支払い方法を持つ
  - 購入金額関連は、商品の金額合計、送料、割引額、税額（内消費税）、総合計を持つ
- 受注は購入商品情報を複数持つ
  - 購入商品情報は、商品 ID、商品名、商品コード、商品個数、商品単価、割引額、商品税率、商品税込みかどうか、商品端数処理方法を持つ
- 受注は支払い情報を複数持つ
  - 支払い情報は、支払い方法、支払い日時、支払い金額、支払い情報ステータスを持つ
- 一括発送処理

  - テンプレート CSV のダウンロード  
    下記の項目が含まれていること
    | Key | Type | memo |
    | -------------- | ------- | ---- |
    | orderId | Integer |受注 ID|
    | shippingCode | String |出荷コード|
    | shippingDate | Date |出荷日|
    | deliveryDate | Date | 配達日|
    | deliveryTimezone | String | 配達時間帯 |
  - CSV の読込  
    上記項目の CSV ファイルを読み込む。  
    読込時に各行のバリデーションチェックを行い、エラーがある場合はエラー内容を表示、エラーがない場合は読込した内容を画面上に一覧表示する。  
    バリデーションチェック項目は以下の通り
    - 必要な Key があるか
    - 型があっているか
  - 出荷情報の更新  
    データの行頭チェックボックスをチェックし、「出荷情報更新」ボタンを押下すると選択したデータに該当する受注情報を更新する。  
    更新が終わったら一覧の各行に更新結果（エラー or 成功）を表示する。  
    更新する項目は以下の通り。

    - Order
      - 受注ステータス
    - OrderDelivery
      - 出荷コード
      - 出荷日
      - 配達日
      - 配達時間帯

    出荷情報更新の際に、以下のケースはエラーとする。

    - 該当の受注が見つからない
    - 受注ステータスが完了になっている

#### 金額計算方式

- 商品金額
  - 商品個数 × 商品単価 × (商品税込みかどうか ? 1 : 商品税率) → 合計に対して端数処理を適用
- 受注金額
  - SUM(購入商品小計) + 送料 - SUM(購入商品割引額) = 総合計
  - 税額（内消費税）は SUM(購入商品小計)に含まれる消費税額を登録する
- 支払い金額
  - SUM(支払い金額) = 受注支払額

#### 定数

- 受注ステータス
  - 受注（登録時）
  - 発送済み（発送時）
  - 完了（発送済み+入金済み）
  - キャンセル（キャンセル時）
- 支払いステータス
  - 未入金（登録時）
  - 一部入金（支払い済みだが金額が足りない）
  - 入金済み（支払い済み）
  - 過入金（支払う済みだが金額が超過）
  - 返金済み（返金時）
- 支払い情報タイプ
  - 与信
  - 速報
  - 完了
- 支払い方法
  - クレジットカード
  - 後払い

#### 支払い情報タイプ

クレジットカードで支払い時は、与信、完了の順に支払い情報を登録する  
購入時に与信を行い、発送時に完了を行う

後払い時には、速報、完了の順に支払い情報を登録する  
外部からの連携時に速報データが来る場合は、速報として登録するが、速報データが来ずに完了データが来る場合は、完了として登録する

受注の支払額には支払い情報タイプが完了となっているものの合算が登録される

## モデル

- Order

| `orders`       | Type    | memo |
| -------------- | ------- | ---- |
| customer_id    | Integer |      |
| total          | Double  |      |
| discount       | Double  |      |
| shipping       | Double  |      |
| tax            | Double  |      |
| grand_total    | Double  |      |
| status         | String  |      |
| paid           | Double  |      |
| payment_status | String  |      |
| payment_method | String  |      |
| note           | String  |      |

- OrderProduct

| `order_products` | Type    | memo |
| ---------------- | ------- | ---- |
| order_id         | Integer |      |
| product_id       | Integer |      |
| name             | String  |      |
| code             | String  |      |
| quantity         | Integer |      |
| price            | Double  |      |
| discount         | Double  |      |
| tax_rate         | Integer |      |
| tax_included     | Boolean |      |
| tax_rounding     | String  |      |

- OrderPayment

| `order_payments` | Type    | memo |
| ---------------- | ------- | ---- |
| order_id         | Integer |      |
| type             | String  |      |
| paid             | Double  |      |
| method           | String  |      |
| paid_at          | Date    |      |

- OrderDelivery

| `order_deliveries` | Type    | memo |
| ------------------ | ------- | ---- |
| order_id           | Integer |      |
| shipping_code      | String  |      |
| shipping_date      | Date    |      |
| delivery_date      | Date    |      |
| delivery_timezone  | String  |      |
