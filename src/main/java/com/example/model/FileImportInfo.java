package com.example.model;

import java.io.Serializable;
import java.time.LocalDateTime;

import com.example.enums.FileImportStatus;
import com.example.enums.ServiceType;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

// ファイル取込ステータステーブル
@Getter
@Setter
@Entity
@Table(name = "file_import_statuses")
public class FileImportInfo extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	// ID
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	// 取込開始日時時刻
	@Column(name = "start_date_time", nullable = false)
	// @DateTimeFormat(pattern = "yyyy-MM-dd")
	private LocalDateTime startDatetime;

	// 取込完了日時時刻
	@Column(name = "end_date_time", nullable = true)
	// @DateTimeFormat(pattern = "yyyy-MM-dd")
	private LocalDateTime endDatetime;

	// 取込ステータス
	// default 0: 取込中
	@Column(name = "status", nullable = false, columnDefinition = "TINYINT(1) default 0")
	private FileImportStatus status;

	// 取込元の関係するテーブルのIDを設定する
	@Column(name = "relation_id", nullable = false)
	private Long relationId;

	// 取込元のサービス
	@Column(name = "type", nullable = false, columnDefinition = "TINYINT(1)")
	private ServiceType type;
}