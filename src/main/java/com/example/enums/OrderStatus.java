package com.example.enums;

/**
 * 受注ステータス定数
 */
public enum OrderStatus {
	Orderd("ordered", "受注"),
	Shipped("shipped", "発送済み"),
	Completed("completed", "完了"),
	Canceled("canceled", "キャンセル");

	/**
	 * 受注
	 */
	public static final String ORDERED = "ordered";
	/**
	 * 発送済み
	 */
	public static final String SHIPPED = "shipped";
	/**
	 * 完了
	 */
	public static final String COMPLETED = "completed";
	/**
	 * キャンセル
	 */
	public static final String CANCELED = "canceled";

	private final String code;
	private final String name;

	private OrderStatus(String code, String name) {
		this.code = code;
		this.name = name;
	}

	public String getCode() {
		return code;
	}

	public String getName() {
		return name;
	}

	public static OrderStatus getOrderStatus(String code) {
		for (OrderStatus orderStatus : OrderStatus.values()) {
			if (orderStatus.getCode().equals(code)) {
				return orderStatus;
			}
		}
		return null;
	}
}
