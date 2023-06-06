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
import com.example.model.Company;
import com.example.service.CompanyService;

/**
 * CompanyControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class CompanyControllerTests {
	@Autowired
	private CompanyService companyService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/companies")).andExpect(status().isOk())
				.andExpect(view().name("company/index")).andExpect(model().attributeExists("listCompany"));
	}

	/**
	 * get showのテスト
	 */
	@Test
	public void getShowTest(@Autowired MockMvc mvc) throws Exception {
		Company company = new Company();
		company.setName("test");
		company.setEmail(UUID.randomUUID().toString() + "@example.com");
		company.setAddress("test");
		company.setPhone("test");
		company.setZipCode("100000");
		companyService.save(company);
		mvc.perform(MockMvcRequestBuilders.get("/companies/" + company.getId())).andExpect(status().isOk())
				.andExpect(view().name("company/show")).andExpect(model().attributeExists("company"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/companies/new")).andExpect(status().isOk())
				.andExpect(view().name("company/form")).andExpect(model().attributeExists("company"));
	}

	/**
	 * post create 失敗 テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/companies").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/companies")).andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(
				MockMvcRequestBuilders.post("/companies")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("name", "test")
						.param("email", UUID.randomUUID().toString() + "@example.com")
						.param("address", "test")
						.param("phone", "test")
						.param("zipCode", "1000000"))
				.andExpect(status().isFound()).andExpect(redirectedUrlPattern("/companies/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class,
				() -> mvc.perform(MockMvcRequestBuilders.get("/companies/999/edit")));
	}

	/**
	 * get update 成功テスト
	 */
	@Test
	public void getUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Company company = new Company();
		company.setName("test");
		company.setEmail(UUID.randomUUID().toString() + "@example.com");
		company.setAddress("test");
		company.setPhone("test");
		company.setZipCode("100000");
		companyService.save(company);

		mvc.perform(MockMvcRequestBuilders.get("/companies/" + company.getId() + "/edit")).andExpect(status().isOk())
				.andExpect(view().name("company/form"))
				.andExpect(model().attribute("company", SamePropertyValuesAs.samePropertyValuesAs(company)));
	}

	/**
	 * put update 失敗 テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.put("/companies").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/companies")).andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * put update 成功 テスト
	 */
	@Test
	public void putUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Company company = new Company();
		company.setName("test");
		company.setEmail(UUID.randomUUID().toString() + "@example.com");
		company.setAddress("test");
		company.setPhone("test");
		company.setZipCode("100000");
		companyService.save(company);
		var email = UUID.randomUUID().toString() + "@example.com";
		mvc.perform(
				MockMvcRequestBuilders.put("/companies")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("id", company.getId().toString())
						.param("name", "test2")
						.param("email", email)
						.param("address", "test2")
						.param("phone", "test2")
						.param("zipCode", "1000001"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/companies/" + company.getId()))

				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<Company> company2 = companyService.findOne(company.getId());
		Assertions.assertEquals("test2", company2.get().getName());
		Assertions.assertEquals(email, company2.get().getEmail());
		Assertions.assertEquals("test2", company2.get().getAddress());
		Assertions.assertEquals("test2", company2.get().getPhone());
		Assertions.assertEquals("1000001", company2.get().getZipCode());
	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc
				.perform(MockMvcRequestBuilders.delete("/companies/999").with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	/**
	 * delete 成功 テスト
	 */
	@Test
	public void deleteValidTest(@Autowired MockMvc mvc) throws Exception {
		Company company = new Company();
		company.setName("test");
		company.setEmail(UUID.randomUUID().toString() + "@example.com");
		company.setAddress("test");
		company.setPhone("test");
		company.setZipCode("100000");
		companyService.save(company);

		mvc.perform(MockMvcRequestBuilders.delete("/companies/" + company.getId())
				.with(SecurityMockMvcRequestPostProcessors.csrf())).andExpect(status().isFound())
				.andExpect(redirectedUrl("/companies"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<Company> company2 = companyService.findOne(company.getId());
		Assertions.assertFalse(company2.isPresent());
	}
}
