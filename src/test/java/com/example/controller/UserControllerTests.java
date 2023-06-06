package com.example.controller;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import jakarta.servlet.ServletException;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Optional;
import java.util.UUID;

import org.hamcrest.beans.SamePropertyValuesAs;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;

import com.example.constants.Message;
import com.example.model.User;
import com.example.service.UserService;

/**
 * UserControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class UserControllerTests {
	@Autowired
	private UserService userService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/users"))
				.andExpect(status().isOk())
				.andExpect(view().name("user/index"))
				.andExpect(model().attributeExists("listUser"));
	}

	/**
	 * get showのテスト
	 */
	@Test
	public void getShowTest(@Autowired MockMvc mvc) throws Exception {
		User user = new User();
		user.setName("test");
		user.setEmail(UUID.randomUUID().toString() + "@example.com");
		user.setPassword("test");
		user.setRole("ADMIN");
		userService.save(user);
		mvc.perform(MockMvcRequestBuilders.get("/users/" + user.getId()))
				.andExpect(status().isOk())
				.andExpect(view().name("user/show"))
				.andExpect(model().attributeExists("user"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/users/new"))
				.andExpect(status().isOk())
				.andExpect(view().name("user/form"))
				.andExpect(model().attributeExists("user"));
	}

	/**
	 * post create 失敗 テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post(
				"/users")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/users"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/users")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("name", "test")
				.param("email", UUID.randomUUID().toString() + "@example.com")
				.param("password", "test"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("/users/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class,
				() -> mvc.perform(MockMvcRequestBuilders.get("/users/999/edit")));
	}

	/**
	 * get update 成功テスト
	 */
	@Test
	public void getUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		User user = new User();
		user.setName("test");
		user.setEmail(UUID.randomUUID().toString() + "@example.com");
		user.setPassword("test");
		user.setRole("USER");
		userService.save(user);

		mvc.perform(MockMvcRequestBuilders.get("/users/" + user.getId() + "/edit"))
				.andExpect(status().isOk())
				.andExpect(view().name("user/form"))
				.andExpect(model().attribute("user", SamePropertyValuesAs.samePropertyValuesAs(user)));
	}

	/**
	 * put update 失敗 テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.put("/users")
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/users"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * put update 成功 テスト
	 */
	@Test
	public void putUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		User user = new User();
		user.setName("test");
		user.setEmail(UUID.randomUUID().toString() + "@example.com");
		user.setPassword("test");
		user.setRole("ADMIN");
		userService.save(user);
		var email = UUID.randomUUID().toString() + "@example.com";
		mvc.perform(MockMvcRequestBuilders.put("/users")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("id", user.getId().toString())
				.param("name", "test2")
				.param("email", email)
				.param("password", "test"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/users/" + user.getId()))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<User> user2 = userService.findOne(user.getId());
		Assertions.assertEquals("test2", user2.get().getName());
		Assertions.assertEquals(email, user2.get().getEmail());
	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc
				.perform(
						MockMvcRequestBuilders.delete("/users/999").with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	/**
	 * delete 成功 テスト
	 */
	@Test
	public void deleteValidTest(@Autowired MockMvc mvc) throws Exception {
		User user = new User();
		user.setName("test");
		user.setEmail(UUID.randomUUID().toString() + "@example.com");
		user.setPassword("test");
		user.setRole("USER");
		userService.save(user);

		mvc.perform(
				MockMvcRequestBuilders.delete("/users/" + user.getId())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/users"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<User> user2 = userService.findOne(user.getId());
		Assertions.assertFalse(user2.isPresent());
	}
}
