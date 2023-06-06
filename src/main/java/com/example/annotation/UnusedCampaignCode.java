package com.example.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import com.example.validate.UnusedCampaignCodeValidator;

import jakarta.validation.Payload;
import jakarta.validation.Constraint;

/**
 * キャンペーンコードの重複チェック用アノテーションクラス.
 */
@Documented
@Constraint(validatedBy = UnusedCampaignCodeValidator.class)
@Target({ ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface UnusedCampaignCode {
	String message() default "すでに登録済みのキャンペーンコードです。"; // エラーメッセージ

	Class<?>[] groups() default {};

	Class<? extends Payload>[] payload() default {};

	@Target({ ElementType.TYPE })
	@Retention(RetentionPolicy.RUNTIME)
	@Documented
	public @interface List {
		UnusedCampaignCode[] value();
	}

	String[] fields();
}
