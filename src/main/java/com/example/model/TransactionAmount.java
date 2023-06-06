package com.example.model;

import java.io.Serializable;
import java.lang.String;
import java.util.Date;

import org.springframework.format.annotation.DateTimeFormat;

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

// 取引先会社情報テーブル
@Getter
@Setter
@Entity
@Table(name = "transaction_amounts")
public class TransactionAmount extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	// ID
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	// 取引先会社ID
	@Column(name = "company_id", nullable = false)
	private Long companyId;

	// 取引先会社リレーション
	@ManyToOne(fetch = FetchType.EAGER)
	@JoinColumn(nullable = false, insertable = false, updatable = false, name = "company_id")
	@JsonIgnore
	private Company company;

	// 収入(+/true)・支出(-/false)
	@Column(name = "plus_minus", nullable = false)
	private Boolean plusMinus;

	// 金額
	@Column(name = "price", nullable = false)
	private Integer price;

	// 期日
	@Column(name = "due_date", nullable = false)
	@DateTimeFormat(pattern = "yyyy-MM-dd")
	private Date dueDate;

	// 対応完了フラグ
	@Column(name = "has_paid", nullable = false)
	private Boolean hasPaid;

	// メモ
	@Column(name = "memo", nullable = false, columnDefinition = "TEXT")
	private String memo;
}
