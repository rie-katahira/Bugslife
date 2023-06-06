package com.example.model;

import java.io.Serializable;
import java.lang.String;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

@Entity
@Table(name = "apps")
public class App extends TimeEntity implements Serializable {

	private static final long serialVersionUID = 1L;

	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Long id;

	@Column(name = "name", nullable = false)
	private String name;

	@Column(name = "url", nullable = false)
	private String url;

	@Column(name = "developer", nullable = false)
	private String developer;

	@Column(name = "description", nullable = false, columnDefinition = "TEXT")
	private String description;

	@Column(name = "image", nullable = false, columnDefinition = "TEXT")
	private String image;

	@Column(name = "active", nullable = false)
	private Boolean active;

	public void setName(String name) {
		this.name = name;
	}

	public String getName() {
		return name;
	}

	public void setUrl(String url) {
		this.url = url;
	}

	public String getUrl() {
		return url;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public void setDeveloper(String developer) {
		this.developer = developer;
	}

	public String getDeveloper() {
		return developer;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getDescription() {
		return description;
	}

	public void setImage(String image) {
		this.image = image;
	}

	public String getImage() {
		return image;
	}

	public Boolean getActive() {
		return active;
	}

	public void setActive(Boolean active) {
		this.active = active;
	}

}
