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

import org.hamcrest.beans.SamePropertyValuesAs;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;

import com.example.constants.Message;
import com.example.model.Category;
import com.example.service.CategoryService;

/**
 * CategoryControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class CategoryControllerTests {
	@Autowired
	private CategoryService categoryService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/categories")).andExpect(status().isOk())
				.andExpect(view().name("category/index")).andExpect(model().attributeExists("listCategory"));
	}

	/**
	 * get showのテスト
	 */
	@Test
	public void getShowTest(@Autowired MockMvc mvc) throws Exception {
		Category category = new Category();
		category.setName("test");
		category.setDescription("42");
		categoryService.save(category);
		mvc.perform(MockMvcRequestBuilders.get("/categories/" + category.getId())).andExpect(status().isOk())
				.andExpect(view().name("category/show")).andExpect(model().attributeExists("category"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/categories/new")).andExpect(status().isOk())
				.andExpect(view().name("category/form")).andExpect(model().attributeExists("category"));
	}

	/**
	 * post create 失敗 テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/categories").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/categories")).andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/categories")
				.param("name", "test").param("description", "42").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("/categories/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class,
				() -> mvc.perform(MockMvcRequestBuilders.get("/categories/999/edit")));
	}

	/**
	 * get update 成功テスト
	 */
	@Test
	public void getUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Category category = new Category();
		category.setName("test");
		category.setDescription("42");
		categoryService.save(category);

		mvc.perform(MockMvcRequestBuilders.get("/categories/" + category.getId() + "/edit")).andExpect(status().isOk())
				.andExpect(view().name("category/form"))
				.andExpect(model().attribute("category", SamePropertyValuesAs.samePropertyValuesAs(category)));
	}

	/**
	 * put update 失敗 テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.put("/categories").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/categories")).andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * put update 成功 テスト
	 */
	@Test
	public void putUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Category category = new Category();
		category.setName("test");
		category.setDescription("42");
		categoryService.save(category);

		mvc.perform(MockMvcRequestBuilders.put("/categories").param("id", category.getId().toString())
				.param("name", "test2").param("description", "43").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/categories/" + category.getId()))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<Category> category2 = categoryService.findOne(category.getId());
		Assertions.assertEquals("test2", category2.get().getName());
		Assertions.assertEquals("43", category2.get().getDescription());
	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class,
				() -> mvc.perform(
						MockMvcRequestBuilders.delete("/categories/999").with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	/**
	 * delete 成功 テスト
	 */
	@Test
	public void deleteValidTest(@Autowired MockMvc mvc) throws Exception {
		Category category = new Category();
		category.setName("test");
		category.setDescription("42");
		categoryService.save(category);

		mvc.perform(MockMvcRequestBuilders.delete("/categories/" + category.getId())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/categories"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<Category> category2 = categoryService.findOne(category.getId());
		Assertions.assertFalse(category2.isPresent());
	}
}
