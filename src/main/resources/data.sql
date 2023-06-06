-- MySQL dump 10.13
-- ※初期データを入れたいときはここにINSERT文を追加してください
-- INSERT IGNORE INTO ...でデータが存在するときのエラーを回避できます。

-- 取引先(companies)初期データ
LOCK TABLES `bugslife`.`companies` WRITE;
INSERT IGNORE INTO `bugslife`.`companies` VALUES
    (1,NOW(),NOW(),'アドレスレス','company@gmail.com','会社その１','08000000000','0000000')
;
UNLOCK TABLES;

-- 取引金額(transaction_amonuts ※related companies)初期データ
LOCK TABLES `bugslife`.`transaction_amounts` WRITE;
INSERT IGNORE INTO `bugslife`.`transaction_amounts` VALUES
    (1,NOW(),NOW(),1,'2023-06-01 00:00:00.000000',_binary '','入金確認済み',_binary '',1000),
    (2,NOW(),NOW(),1,'2023-06-15 00:00:00.000000',_binary '\0','期限までの支払いが必要',_binary '\0',100000)
;
UNLOCK TABLES;
