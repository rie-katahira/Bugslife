package com.example.controller.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.UUID;

import com.example.json.api.Authenticate;
import com.example.model.User;
import com.example.service.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class AuthenticateControllerTests {
	@Autowired
	private UserService userService;

	/**
	 * post authenticateのテスト
	 */
	@Test
	public void postAuthenticateTest(@Autowired MockMvc mvc) throws Exception {
		var objectMapper = new ObjectMapper();
		/**
		 * ユーザーが存在しない場合
		 */
		var requestParam = new Authenticate.RequestBody();
		requestParam.setEmail(UUID.randomUUID().toString() + "@example.com");
		requestParam.setPassword("test");
		mvc.perform(MockMvcRequestBuilders.post("/api/authenticate").content(objectMapper.writeValueAsString(requestParam))
				.contentType(MediaType.APPLICATION_JSON)
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isBadRequest());

		User user = new User();
		user.setName("test");
		user.setEmail(UUID.randomUUID().toString() + "@example.com");
		user.setPassword("test");
		userService.save(user);

		/**
		 * パスワードが一致しない場合
		 */
		requestParam.setEmail(user.getEmail());
		requestParam.setPassword("test2");
		mvc.perform(MockMvcRequestBuilders.post("/api/authenticate").content(objectMapper.writeValueAsString(requestParam))
				.contentType(MediaType.APPLICATION_JSON).with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isBadRequest());

		/**
		 * 正常系
		 */
		requestParam.setEmail(user.getEmail());
		requestParam.setPassword("test");

		mvc.perform(MockMvcRequestBuilders.post("/api/authenticate").content(objectMapper.writeValueAsString(requestParam))
				.contentType(MediaType.APPLICATION_JSON).with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isOk());
	}

	/**
	 * get verifyTokenのテスト
	 */
	@Test
	public void getVerifyTokenTest(@Autowired MockMvc mvc) throws Exception {
		/**
		 * ユーザーの作成
		 */
		User user = new User();
		user.setName("test");
		user.setEmail(UUID.randomUUID().toString() + "@example.com");
		user.setPassword("test");
		userService.save(user);

		/**
		 * リクエストパラメータの作成
		 */
		var objectMapper = new ObjectMapper();
		var requestParam = new Authenticate.RequestBody();
		requestParam.setEmail(user.getEmail());
		requestParam.setPassword("test");

		/**
		 * トークンの生成
		 */
		var result = mvc.perform(MockMvcRequestBuilders.post("/api/authenticate")
				.content(objectMapper.writeValueAsString(requestParam)).contentType(MediaType.APPLICATION_JSON)
				.with(SecurityMockMvcRequestPostProcessors.csrf())).andReturn()
				.getResponse().getContentAsString();

		/**
		 * 正常系
		 */
		var verify = mvc
				.perform(MockMvcRequestBuilders.get("/api/authenticate/verifyToken").header("Authorization",
						"Bearer " + objectMapper.readTree(result).get("token").asText()))
				.andExpect(status().isOk()).andReturn().getResponse().getContentAsString();

		Assertions.assertEquals("{\"result\":\"OK\"}", verify);

	}

}
