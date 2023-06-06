package com.example.form;

import lombok.Getter;
import lombok.Setter;

@Setter
@Getter
public class UserSearchForm {
	private String name;

	public UserSearchForm(String name) {
		this.setName(name);
	}
}
