package com.example.enums;

public enum PaymentMethod {

	CreditCard("credit_card", "クレジットカード"),
	DefferedPayment("deffered_payment", "後払い");

	/**
	 * クレジットカード
	 */
	public final static String CREDIT_CARD = "credit_card";
	/**
	 * 後払い
	 */
	public final static String PAYMENT_ON_DELIVERY = "payment_on_delivery";

	private final String code;
	private final String name;

	private PaymentMethod(String code, String name) {
		this.code = code;
		this.name = name;
	}

	public String getCode() {
		return code;
	}

	public String getName() {
		return name;
	}

	public static PaymentMethod getPaymentMethod(String code) {
		for (PaymentMethod paymentMethod : PaymentMethod.values()) {
			if (paymentMethod.getCode().equals(code)) {
				return paymentMethod;
			}
		}
		return null;
	}
}
