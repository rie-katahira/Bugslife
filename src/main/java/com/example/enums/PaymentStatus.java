package com.example.enums;

/**
 * 支払いステータス定数
 */
public enum PaymentStatus {
	UnPaid("unpaid", "未入金"),
	PartiallyPaid("partially_paid", "一部入金"),
	Paid("paid", "入金済み"),
	OverPaid("overpaid", "過入金"),
	Refunded("refunded", "返金");

	/**
	 * 未入金
	 */
	public static final String UNPAID = "unpaid";
	/**
	 * 一部入金
	 */
	public static final String PARTIALLY_PAID = "partially_paid";
	/**
	 * 入金済み
	 */
	public static final String PAID = "paid";
	/**
	 * 過入金
	 */
	public static final String OVERPAID = "overpaid";
	/**
	 * 返金
	 */
	public static final String REFUNDED = "refunded";

	private final String code;
	private final String name;

	private PaymentStatus(String code, String name) {
		this.code = code;
		this.name = name;
	}

	public String getCode() {
		return code;
	}

	public String getName() {
		return name;
	}

	public static PaymentStatus getPaymentStatus(String code) {
		for (PaymentStatus paymentStatus : PaymentStatus.values()) {
			if (paymentStatus.getCode().equals(code)) {
				return paymentStatus;
			}
		}
		return null;
	}
}
