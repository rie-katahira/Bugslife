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
import com.example.form.ProductForm;
import com.example.model.Product;
import com.example.model.Shop;
import com.example.service.ProductService;
import com.example.service.ShopService;

/**
 * ShopProductControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class ShopProductControllerTests {
	@Autowired
	private ProductService productService;

	@Autowired
	private ShopService shopService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);

		mvc.perform(MockMvcRequestBuilders.get("/shops/" + shop.getId() + "/products"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop_product/index"))
				.andExpect(model().attributeExists("listProduct"));
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

		Product product = new Product();
		product.setShopId(shop.getId());
		product.setName("test");
		product.setCode("42");
		product.setWeight(42);
		product.setHeight(42);
		product.setPrice(42);
		product.setTaxType(1);
		productService.save(product);
		mvc.perform(MockMvcRequestBuilders.get("/shops/" + shop.getId() + "/products/" + product.getId()))
				.andExpect(status().isOk())
				.andExpect(view().name("shop_product/show"))
				.andExpect(model().attributeExists("product"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);
		mvc.perform(MockMvcRequestBuilders.get("/shops/" + shop.getId() + "/products/new"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop_product/form"))
				.andExpect(model().attributeExists("productForm"));
	}

	/**
	 * post create バリデーションエラー テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);
		mvc.perform(
				MockMvcRequestBuilders.post("/shops/" + shop.getId() + "/products")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("name", "test"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop_product/form"))
				.andExpect(model().attributeExists("productForm"))
				.andExpect(model().hasErrors())
				.andExpect(model().attributeHasErrors("productForm"));
	}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);
		mvc.perform(
				MockMvcRequestBuilders.post("/shops/" + shop.getId() + "/products")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("shopId", shop.getId().toString())
						.param("name", "test")
						.param("code", "42")
						.param("categoryIds", "")
						.param("weight", "42")
						.param("height", "42")
						.param("price", "42")
						.param("rate", "10")
						.param("taxIncluded", "true")
						.param("rounding", "floor"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("/shops/" + shop.getId() + "/products/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class,
				() -> mvc.perform(MockMvcRequestBuilders.get("/shops/1/products/999/edit")));
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

		Product product = new Product();
		product.setShopId(shop.getId());
		product.setName("test");
		product.setCode("42");
		product.setWeight(42);
		product.setHeight(42);
		product.setPrice(42);
		product.setTaxType(1);
		productService.save(product);

		mvc.perform(MockMvcRequestBuilders.get("/shops/" + shop.getId() + "/products/" + product.getId() + "/edit"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop_product/form"))
				.andExpect(model().attribute("productForm", SamePropertyValuesAs.samePropertyValuesAs(new ProductForm(product))));
	}

	/**
	 * put update バリデーションエラー テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Shop shop = new Shop();
		shop.setName("test");
		shop.setAddress("42");
		shop.setContact("42");
		shopService.save(shop);
		mvc.perform(
				MockMvcRequestBuilders.put("/shops/" + shop.getId() + "/products")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("name", "test"))
				.andExpect(status().isOk())
				.andExpect(view().name("shop_product/form"))
				.andExpect(model().hasErrors())
				.andExpect(model().attributeHasErrors("productForm"));
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

		Product product = new Product();
		product.setShopId(shop.getId());
		product.setName("test");
		product.setCode("42");
		product.setWeight(42);
		product.setHeight(42);
		product.setPrice(42);
		product.setTaxType(1);
		productService.save(product);

		mvc.perform(MockMvcRequestBuilders.put("/shops/" + shop.getId() + "/products")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("id", product.getId().toString())
				.param("shopId", shop.getId().toString())
				.param("name", "test2")
				.param("code", "43")
				.param("categoryIds", "")
				.param("weight", "43")
				.param("height", "43")
				.param("price", "42")
				.param("rate", "10")
				.param("taxIncluded", "true")
				.param("rounding", "floor"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/shops/" + shop.getId() + "/products/" + product.getId()))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<Product> product2 = productService.findOne(product.getId());
		Assertions.assertEquals("test2", product2.get().getName());
		Assertions.assertEquals("43", product2.get().getCode());
		Assertions.assertEquals(43, product2.get().getWeight());
		Assertions.assertEquals(43, product2.get().getHeight());
		Assertions.assertEquals(42, product2.get().getPrice());
		Assertions.assertEquals(16, product2.get().getTaxType());

	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc
				.perform(MockMvcRequestBuilders.delete("/shops/1/products/999").with(SecurityMockMvcRequestPostProcessors.csrf())));
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

		Product product = new Product();
		product.setShopId(shop.getId());
		product.setName("test");
		product.setCode("42");
		product.setWeight(42);
		product.setHeight(42);
		product.setPrice(42);
		product.setTaxType(1);
		productService.save(product);

		mvc.perform(MockMvcRequestBuilders.delete("/shops/" + shop.getId() + "/products/" + product.getId())
				.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/shops/" + shop.getId() + "/products"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<Product> product2 = productService.findOne(product.getId());
		Assertions.assertFalse(product2.isPresent());
	}
}
