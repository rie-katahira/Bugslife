package com.example.utils;

import com.example.constants.Validate;
import java.util.Objects;

public class CheckUtil {

	/**
	 * descriptionの文字数チェックを行う
	 *
	 * @param description
	 * @return boolean
	 */
	public static boolean checkDescriptionLength(String description) {
		// descriptionは2000文字以下か
		if (Objects.nonNull(description) && description.length() > Validate.TEXT_LENGTH) {
			return false;
		}
		return true;
	}
}
