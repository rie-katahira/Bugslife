package com.example.validate;

import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;
import org.springframework.beans.factory.annotation.Autowired;

import com.example.annotation.UnusedCampaignCode;
import com.example.model.Campaign;
import com.example.service.CampaignService;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;

/**
 * キャンペーンコードの重複チェック用バリデーションクラス.
 */
public class UnusedCampaignCodeValidator implements ConstraintValidator<UnusedCampaignCode, Object> {

	@Autowired
	private CampaignService service;

	// バリデーション対象のフィールド
	private String[] fields;

	// エラーメッセージ
	private String message;

	/**
	 * 初期化処理.
	 */
	public void initialize(UnusedCampaignCode constraintAnnotation) {
		// アノテーションクラスのパラメータを取得
		this.fields = constraintAnnotation.fields();
		this.message = constraintAnnotation.message();
	}

	/**
	 * バリデーション処理.
	 *
	 * @param bean    バリデーション対象のオブジェクト
	 * @param context バリデーションコンテキスト
	 * @return バリデーション結果
	 */
	@Override
	@SuppressWarnings("unused")
	public boolean isValid(Object bean, ConstraintValidatorContext context) {
		BeanWrapper beanWrapper = new BeanWrapperImpl(bean);
		// 画面で入力したキャンペーンのIDとコードを取得
		Long id = (Long)beanWrapper.getPropertyValue(fields[0]);
		String code = (String)beanWrapper.getPropertyValue(fields[1]);

		// 画面で入力したキャンペーンコードを元にDBからキャンペーンを取得
		Campaign campaign = service.findByCode(code).orElse(null);

		// 登録済みのキャンペーンが存在しない場合は重複チェックを行わない
		// かつ画面で入力したキャンペーンのIDとDBから取得したキャンペーンのIDが一致する場合は重複チェックを行わない
		if (campaign == null) {
			return true;
		}
		context.disableDefaultConstraintViolation();
		context.buildConstraintViolationWithTemplate(message).addPropertyNode(fields[1])
				.addConstraintViolation();

		return false;
	}
}
