package com.example.enums;

public enum CampaignStatus {
	Pending(0, "保留"),
	Eligible(1, "有効"),
	Paused(2, "一時停止"),
	Removed(3, "削除"),
	Ended(4, "終了");

	private final int id;
	private final String name;

	private CampaignStatus(int id, String name) {
		this.id = id;
		this.name = name;
	}

	public static CampaignStatus valueOf(int id) {
		for (CampaignStatus status : values()) {
			if (status.getId() == id) {
				return status;
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
