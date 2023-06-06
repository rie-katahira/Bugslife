package com.example.model;

import java.io.Serializable;

import com.fasterxml.jackson.annotation.JsonIgnore;

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

@Getter
@Setter
@Entity
@Table(name = "categories_products")
public class CategoryProduct extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "category_id", nullable = false)
	private Long categoryId;

	@Column(name = "product_id", nullable = false)
	private Long productId;

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(nullable = true, insertable = false, updatable = false, name = "category_id")
	@JsonIgnore
	private Category category;

	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(nullable = true, insertable = false, updatable = false, name = "product_id")
	@JsonIgnore
	private Product product;

	public CategoryProduct() {}

	public CategoryProduct(Long categoryId, Long productId) {
		this.setCategoryId(categoryId);
		this.setProductId(productId);
	}

}
