package com.example.model;

import java.io.Serializable;
import java.lang.String;
import java.util.List;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;

// 取引先会社情報テーブル
@Entity
@Table(name = "companies")
public class Company extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	// ID
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	// 取引先会社名
	@Column(name = "name", nullable = false)
	private String name;

	// メールアドレス
	@Column(name = "email", nullable = false)
	private String email;

	// 住所
	@Column(name = "address", nullable = false)
	private String address;

	// 電話番号
	@Column(name = "phone", nullable = false)
	private String phone;

	// 郵便番号
	@Column(name = "zip_code", nullable = false)
	private String zipCode;

	// 取引額
	@OneToMany(mappedBy = "company", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private List<TransactionAmount> transactionAmounts;

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getEmail() {
		return email;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getAddress() {
		return address;
	}

	public void setPhone(String phone) {
		this.phone = phone.replaceAll("[^0-9]", "");
	}

	public String getPhone() {
		return phone;
	}

	public String getZipCode() {
		return zipCode;
	}

	public void setZipCode(String zip_code) {
		this.zipCode = zip_code.replaceAll("[^0-9]", "");
	}
}
