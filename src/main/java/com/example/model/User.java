package com.example.model;

import java.io.Serializable;
import java.lang.String;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Index;
import jakarta.persistence.Table;

@Entity
@Table(name = "users", indexes = @Index(name = "idx_email", columnList = "email"))
public class User extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	public enum Roles {
		ADMIN("ADMIN", "管理者", new String[] { "ADMIN", "USER" }),
		USER("USER", "ユーザー", new String[] { "USER" });

		private final String value;
		private final String viewName;
		private final String[] role;

		private Roles(String value, String viewName, String[] role) {
			this.value = value;
			this.viewName = viewName;
			this.role = role;
		}

		public String getValue() {
			return this.value;
		}

		public String getViewName() {
			return this.viewName;
		}

		public String[] getRole() {
			return this.role;
		}
	}

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "name", nullable = false)
	private String name;

	@Column(name = "email", nullable = false)
	private String email;

	@Column(name = "password", nullable = false)
	private String password;

	@Column(name = "role", nullable = false)
	private String role;

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getEmail() {
		return email;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getPassword() {
		return password;
	}

	public void setRole(String role) {
		this.role = role;
	}

	public String getRole() {
		return role;
	}

	public Roles getRoleEnum() {
		for (Roles role : Roles.values()) {
			if (role.getValue().equals(this.role)) {
				return role;
			}
		}
		throw new IllegalArgumentException("Invalid role value: " + this.role);
	}
}
