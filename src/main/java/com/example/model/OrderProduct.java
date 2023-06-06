package com.example.model;

import java.io.Serializable;
import java.lang.String;

import com.example.constants.TaxType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
@Table(name = "order_products")
public class OrderProduct extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "product_id", nullable = false)
	private Long productId;

	@Column(name = "name", nullable = false)
	private String name;

	@Column(name = "code", nullable = false)
	private String code;

	@Column(name = "quantity", nullable = false)
	private Integer quantity;

	@Column(name = "price", nullable = false)
	private Double price;

	@Column(name = "discount", nullable = false)
	private Double discount;

	@Column(name = "tax_rate", nullable = false)
	private Integer taxRate;

	@Column(name = "tax_included", nullable = false)
	private Boolean taxIncluded;

	@Column(name = "tax_rounding", nullable = false)
	private String taxRounding;

	public void setTaxType(TaxType.Tax tax) {
		this.setTaxRate(tax.rate);
		this.setTaxIncluded(tax.taxIncluded);
		this.setTaxRounding(tax.rounding);
	}
}
