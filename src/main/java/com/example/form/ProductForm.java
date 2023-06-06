package com.example.form;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

import com.example.constants.TaxType;
import com.example.model.CategoryProduct;
import com.example.model.Product;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Setter
@Getter
@NoArgsConstructor
public class ProductForm {

	private Long id;

	@NotNull
	private Long shopId;

	@NotBlank(message = "商品名を入力してください。")
	@Size(max = 255, message = "商品名は255文字以内で入力してください。")
	private String name;

	@NotBlank(message = "商品コードを入力してください。")
	@Size(max = 255, message = "商品コードは255文字以内で入力してください。")
	private String code;

	@Valid
	private List<Long> categoryIds = new ArrayList<Long>();

	@NotNull(message = "重さを入力してください。")
	private Integer weight;

	@NotNull(message = "高さを入力してください。")
	private Integer height;

	@NotNull(message = "値段を入力してください。")
	private Integer price;

	@NotNull(message = "税率を選択してください。")
	private Integer rate = TaxType.RATE_10;

	@NotNull(message = "入力価格を選択してください。")
	private Boolean taxIncluded = false;

	@NotNull(message = "端数処理を選択してください。")
	private String rounding = TaxType.ROUND;


	public ProductForm(Product product) {
		this.setId(product.getId());
		this.setShopId(product.getShopId());
		this.setName(product.getName());
		this.setCode(product.getCode());
		// 紐づくカテゴリIDのリストを作成
		List<CategoryProduct> categoryProducts = product.getCategoryProducts();
		if (categoryProducts != null) {
			List<Long> categoryIds = categoryProducts.stream().map(categoryProduct -> categoryProduct.getCategoryId()).collect(Collectors.toList());
			this.setCategoryIds(categoryIds);
		}
		this.setWeight(product.getWeight());
		this.setHeight(product.getHeight());
		this.setPrice(product.getPrice());
		var tax = TaxType.get(product.getTaxType());
		this.setRate(tax.rate);
		this.setTaxIncluded(tax.taxIncluded);
		this.setRounding(tax.rounding);
	}

	public Integer getTaxType() {
		var tax = TaxType.get(rate, taxIncluded, rounding);
		return tax.id;
	}
}
