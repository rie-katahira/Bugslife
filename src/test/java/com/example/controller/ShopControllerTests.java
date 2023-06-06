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
import com.example.model.Shop;
import com.example.service.ShopService;

/**
 * ShopControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class ShopControllerTests {
	@Autowired
	private ShopService shopService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/shops"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop/index"))
				.andExpect(model().attributeExists("listShop"));
	}

	/**
	 * get showのテスト
	 */
	@Test
	public void getShowTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);
		mvc.perform(MockMvcRequestBuilders.get("/shops/" + shop.getId()))
				.andExpect(status().isOk())
				.andExpect(view().name("shop/show"))
				.andExpect(model().attributeExists("shop"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/shops/new"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop/form"))
				.andExpect(model().attributeExists("shop"));
	}

	/**
	 * post create バリデーションエラー テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(
				MockMvcRequestBuilders.post("/shops")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("name", "test"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop/form"))
				.andExpect(model().hasErrors())
				.andExpect(model().attributeHasErrors("shop"));
			}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(
				MockMvcRequestBuilders.post("/shops")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("name", "test")
						.param("address", "42")
						.param("contact", "42"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("/shops/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc.perform(MockMvcRequestBuilders.get("/shops/999/edit")));
	}

	/**
	 * get update 成功テスト
	 */
	@Test
	public void getUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);

		mvc.perform(MockMvcRequestBuilders.get("/shops/" + shop.getId() + "/edit"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop/form"))
				.andExpect(model().attribute("shop", SamePropertyValuesAs.samePropertyValuesAs(shop)));
	}

	/**
	 * put update バリデーションエラー テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {

		
		mvc.perform(
				MockMvcRequestBuilders.post("/shops")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("name", "test"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop/form"))
				.andExpect(model().hasErrors())
				.andExpect(model().attributeHasErrors("shop"));
	}

	/**
	 * put update 成功 テスト
	 */
	@Test
	public void putUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);

		mvc.perform(
				MockMvcRequestBuilders.put("/shops")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("id", shop.getId().toString())
						.param("name", "test2")
						.param("address", "43")
						.param("contact", "43"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/shops/" + shop.getId()))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<Shop> shop2 = shopService.findOne(shop.getId());
		Assertions.assertEquals("test2", shop2.get().getName());
		Assertions.assertEquals("43", shop2.get().getAddress());
		Assertions.assertEquals("43", shop2.get().getContact());
	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc
				.perform(MockMvcRequestBuilders.delete("/shops/999").with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	/**
	 * delete 成功 テスト
	 */
	@Test
	public void deleteValidTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);

		mvc.perform(
				MockMvcRequestBuilders.delete("/shops/" + shop.getId()).with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/shops"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<Shop> shop2 = shopService.findOne(shop.getId());
		Assertions.assertFalse(shop2.isPresent());
	}
}
