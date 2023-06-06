package com.example.model;

import java.io.Serializable;
import java.lang.String;

import com.example.annotation.UnusedCampaignCode;
import com.example.enums.CampaignStatus;
import com.example.enums.DiscountType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

@Entity
@Table(name = "campaigns")
@Getter
@Setter
@NoArgsConstructor
@UnusedCampaignCode(fields = { "id", "code" }) // キャンペーンコード重複チェック用カスタムアノテーション
public class Campaign extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "name", nullable = false)
	@Size(min = 1, max = 100, message = "キャンペーン名は1文字以上100文字以下で入力してください。")
	@NotEmpty(message = "キャンペーン名を入力してください。")
	private String name;

	@Column(name = "code", nullable = false)
	private String code;

	@Column(name = "from_date", nullable = false)
	private String fromDate;

	@Column(name = "to_date", nullable = false)
	private String toDate;

	@Enumerated(EnumType.ORDINAL)
	@Column(name = "discount_type", nullable = false)
	private DiscountType discountType = DiscountType.valueOf(0);

	@Enumerated(EnumType.ORDINAL)
	@Column(name = "status", nullable = false)
	private CampaignStatus status = CampaignStatus.valueOf(0);

	@Column(name = "description", nullable = false, columnDefinition = "TEXT")
	private String description;

	public Campaign(String name, String code, String fromDate, String toDate, DiscountType discountType,
			CampaignStatus status, String description) {
		this.name = name;
		this.code = code;
		this.fromDate = fromDate;
		this.toDate = toDate;
		this.discountType = discountType;
		this.status = status;
		this.description = description;

	}
}
