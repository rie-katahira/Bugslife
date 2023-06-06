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
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

@Entity
@Table(name = "shops")
public class Shop extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "name", nullable = false)
	@NotBlank(message = "ショップ名を入力してください。")
	@Size(max = 255, message = "ショップ名は255文字以内で入力してください。")
	private String name;

	@Column(name = "address", nullable = false)
	@NotBlank(message = "アドレスを入力してください。")
	@Size(max = 255, message = "アドレスは255文字以内で入力してください。")
	private String address;

	@Column(name = "contact", nullable = false)
	@NotBlank(message = "コンタクトを入力してください。")
	@Size(max = 255, message = "コンタクトは255文字以内で入力してください。")
	private String contact;

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setAddress(String address) {
		this.address = address;
	}

	public String getAddress() {
		return address;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public void setContact(String contact) {
		this.contact = contact;
	}

	public String getContact() {
		return contact;
	}

	@OneToMany(mappedBy = "shop", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private List<Product> products;
}
