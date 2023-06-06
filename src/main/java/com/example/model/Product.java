package com.example.model;

import java.io.Serializable;
import java.lang.String;
import java.util.List;

import com.example.form.ProductForm;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.OneToMany;

@Getter
@Setter
@Entity
@Table(name = "products")
public class Product extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "shop_id", nullable = false)
	private Long shopId;

	@Column(name = "name", nullable = false)
	private String name;

	@Column(name = "code", nullable = false)
	private String code;

	@Column(name = "weight", nullable = false)
	private Integer weight;

	@Column(name = "height", nullable = false)
	private Integer height;

	@Column(name = "price", nullable = false)
	private Integer price;

	@Column(name = "tax_type", nullable = false)
	private Integer taxType;

	public Product() {}

	public Product(ProductForm form) {
		if (form.getId() != null) {
			this.setId(form.getId());
		}
		this.setShopId(form.getShopId());
		this.setName(form.getName());
		this.setCode(form.getCode());
		this.setWeight(form.getWeight());
		this.setHeight(form.getHeight());
		this.setPrice(form.getPrice());
		this.setTaxType(form.getTaxType());
	}

	@OneToMany(mappedBy = "product", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
	private List<CategoryProduct> categoryProducts;

	@ManyToOne(fetch = FetchType.LAZY)
	@JoinColumn(name = "shop_id", insertable = false, updatable = false)
	private Shop shop;
}
