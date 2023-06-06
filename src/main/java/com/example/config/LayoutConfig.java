package com.example.config;

import org.springframework.context.annotation.Configuration;

import nz.net.ultraq.thymeleaf.layoutdialect.LayoutDialect;

import org.springframework.context.annotation.Bean;

@Configuration
public class LayoutConfig {

	// thymeleaf layout
	@Bean
	LayoutDialect layoutDialect() {
		return new LayoutDialect();
	}
}
