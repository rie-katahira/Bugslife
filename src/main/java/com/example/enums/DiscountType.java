package com.example.enums;

public enum DiscountType {
	PercentageSale(0, "パーセント引き"),
	EarlyPaymentDiscount(1, "早期割引"),
	OverstockSale(2, "在庫処分"),
	FreeShippingDiscount(3, "送料無料"),
	BulkDiscount(4, "まとめ買い割引"),
	SeasonalDiscount(5, "季節割引"),
	ReferralDiscount(6, "紹介割引"),
	OneTimeDiscount(7, "一回限りの割引"),
	LoyaltyDiscount(8, "リピーター割引"),
	TradeInDiscount(9, "下取り割引");

	private final int id;
	private final String name;

	private DiscountType(int id, String name) {
		this.id = id;
		this.name = name;
	}

	public static DiscountType valueOf(int id) {
		for (DiscountType type : values()) {
			if (type.getId() == id) {
				return type;
			}
		}
		return null;
	}

	public int getId() {
		return id;
	}

	public String getName() {
		return name;
	}
}
