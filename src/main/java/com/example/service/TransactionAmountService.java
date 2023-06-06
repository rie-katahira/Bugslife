package com.example.service;

import org.apache.commons.lang3.BooleanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.constants.Validate;
import com.example.enums.FileImportStatus;
import com.example.enums.ServiceType;
import com.example.model.Company;
import com.example.model.FileImportInfo;
import com.example.model.TransactionAmount;
import com.example.repository.FileImportInfoRepository;
import com.example.repository.TransactionAmountRepository;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class TransactionAmountService {

	@Autowired
	private TransactionAmountRepository transactionAmountRepository;

	@Autowired
	private FileImportInfoRepository fileImportInfoRepository;

	public List<TransactionAmount> findAll() {
		return transactionAmountRepository.findAll();
	}

	public Optional<TransactionAmount> findOne(Long id) {
		return transactionAmountRepository.findById(id);
	}

	public List<TransactionAmount> findByCompany(Company company) {
		return transactionAmountRepository.findByCompany(company);
	}

	@Transactional(readOnly = false)
	public TransactionAmount save(TransactionAmount entity) {
		return transactionAmountRepository.save(entity);
	}

	@Transactional(readOnly = false)
	public void delete(TransactionAmount entity) {
		transactionAmountRepository.delete(entity);
	}

	/**
	 * 入力値のバリデーションチェックを行う
	 *
	 * @param entity
	 * @return boolean
	 */
	public boolean validate(TransactionAmount entity) {
		// 収支が選択されているか
		if (Objects.isNull(entity.getPlusMinus())) {
			return false;
		}
		// 金額が入力されているか
		if (Objects.isNull(entity.getPrice())) {
			return false;
		}
		// 金額が0以上か
		if (entity.getPrice() <= 0) {
			return false;
		}
		// 金額が10億円以下か
		if (entity.getPrice() >= Validate.PRICE_UPPER) {
			return false;
		}
		// 支出の場合、金額が5億以下か
		if (Objects.isNull(entity.getPlusMinus()) && entity.getPrice() >= Validate.EXPENSE_PRICE_UPPER) {
			return false;
		}
		// メモは1000文字以下か
		if (Objects.nonNull(entity.getMemo())) {
			if (entity.getMemo().length() >= Validate.TEXT_LENGTH) {
				return false;
			}
		}

		return true;
	}

	/**
	 * TransactionalAmountの収支合計を取得する
	 *
	 * @param company
	 * @return Integer
	 */
	public Integer getSumTransactionalAmounts(Company company) {
		List<TransactionAmount> tAmountList = this.findByCompany(company);

		// 収入の場合は加算、支出の場合は減算
		Integer sum = 0;
		for (TransactionAmount tAmount : tAmountList) {
			if (tAmount.getPlusMinus()) {
				sum += tAmount.getPrice();
			} else {
				sum -= tAmount.getPrice();
			}
		}

		// 表示はXXX千円とするので、1000で割って余りは切り捨てて丸める
		sum = (int)Math.round((double)sum / 1000);

		return sum;
	}

	/**
	 * 収支比率を計算する
	 */
	public Integer getRatioTransactionalAmounts(Company company) {
		// 現在の取得を行う
		List<TransactionAmount> tAmountList = this.findByCompany(company);

		// 収入と支出の比率を計算する
		Integer incomSum = 0;
		Integer expenseSum = 0;
		for (TransactionAmount tAmount : tAmountList) {
			if (tAmount.getPlusMinus()) {
				incomSum += tAmount.getPrice();
			} else {
				expenseSum += tAmount.getPrice();
			}
		}
		double ratio = incomSum / (expenseSum + incomSum);
		return (int)Math.round(ratio * 100);
	}

	/**
	 * 非同期で取引金額のCSVファイルを取り込む
	 *
	 * @param file
	 * @param companyId
	 * @throws Exception
	 * @return void
	 * @todo 非同期化
	 */
	@Transactional
	public void importCSV(MultipartFile file, Long companyId) throws Exception {
		// アップデート後のインスタンス
		FileImportInfo updatedImp;
		SimpleDateFormat sdFormat = new SimpleDateFormat("yyyy-MM-dd");

		// CSV取込親テーブルに取込中でデータを登録する
		try {
			// CSV取込親テーブルのインスタンスを生成
			FileImportInfo imp = new FileImportInfo();
			// CSV取込親テーブルのインスタンスにデータをセットする
			imp.setStartDatetime(LocalDateTime.now());
			imp.setStatus(FileImportStatus.IMPORTING);
			imp.setRelationId(companyId);
			imp.setType(ServiceType.COMPANY);
			// CSV取込親テーブルにデータを登録する
			updatedImp = fileImportInfoRepository.save(imp);
		} catch (Exception e) {
			// エラーはコントローラーで処理
			e.printStackTrace();
			throw e;
		}

		// CSVファイルの読み込み
		try (BufferedReader br = new BufferedReader(
				new InputStreamReader(file.getInputStream(), StandardCharsets.UTF_8))) {
			String line;
			int lineCouter = 0;
			while ((line = br.readLine()) != null) {
				// 行数カウントアップ
				lineCouter++;

				// 1行目はヘッダーなので読み飛ばす
				if (lineCouter == 1) {
					continue;
				}

				// csvなのでカンマ区切りで分割する
				final String[] split = line.replace("\"", "").split(",");

				// 取引金額のインスタンスを生成
				TransactionAmount transactionAmount = new TransactionAmount();
				transactionAmount.setCompanyId(companyId);

				// 取引金額のインスタンスにCSVファイルから読み取ったデータをセットする
				transactionAmount.setPlusMinus(BooleanUtils.toBoolean(split[0]));
				transactionAmount.setPrice(Integer.parseInt(split[1]));
				transactionAmount.setDueDate(sdFormat.parse(split[2]));
				transactionAmount.setHasPaid(Boolean.parseBoolean(split[3]));
				transactionAmount.setMemo(split[4]);

				// 取引金額を保存する
				transactionAmountRepository.save(transactionAmount);
			}
			updatedImp.setStatus(FileImportStatus.COMPLETE);
		} catch (Exception e) {
			// 失敗の場合、ステータスをエラーにする
			updatedImp.setStatus(FileImportStatus.ERROR);
			// エラーはコントローラーで処理
			e.printStackTrace();
			throw e;
		} finally {
			// 取込完了日時をセットして処理終了
			updatedImp.setEndDatetime(LocalDateTime.now());
			fileImportInfoRepository.save(updatedImp);
		}
	}
}
