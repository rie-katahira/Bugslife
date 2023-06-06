package com.example.model;

import java.sql.Timestamp;

import jakarta.persistence.Column;
import jakarta.persistence.MappedSuperclass;
import jakarta.persistence.PrePersist;
import jakarta.persistence.PreUpdate;

@MappedSuperclass
public class TimeEntity {
	@Column(name = "create_at", updatable = false, nullable = false)
	private Timestamp createAt;
	@Column(name = "update_at", nullable = false)
	private Timestamp updateAt;

	/**
	 * Getter CreateAt
	 */
	public Timestamp getCreateAt() {
		return createAt;
	}

	/**
	 * Setter CreateAt
	 */
	public void setCreateAt(Timestamp createAt) {
		this.createAt = createAt;
	}

	/**
	 * Getter UpdateAt
	 */
	public Timestamp getUpdateAt() {
		return updateAt;
	}

	/**
	 * Setter UpdateAt
	 */
	public void setUpdateAt(Timestamp updateAt) {
		this.updateAt = updateAt;
	}

	@PrePersist
	public void onPrePersist() {
		setCreateAt(new Timestamp(System.currentTimeMillis()));
		setUpdateAt(new Timestamp(System.currentTimeMillis()));
	}

	@PreUpdate
	public void onPreUpdate() {
		setUpdateAt(new Timestamp(System.currentTimeMillis()));
	}
}
