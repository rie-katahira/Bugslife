package com.example.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Getter
@Setter
@NoArgsConstructor
public class ProductWithCategoryName {

	private Long id;

	private String name;

	private String code;

	private Integer weight;

	private Integer height;

	private Integer price;

	private String categoryName;

	public ProductWithCategoryName(Long id, String code, String name, Integer weight, Integer height, Integer price, String categoryName) {
		this.setId(id);
		this.setCode(code);
		this.setName(name);
		this.setWeight(weight);
		this.setHeight(height);
		this.setPrice(price);
		this.setCategoryName(categoryName);
	}
}
