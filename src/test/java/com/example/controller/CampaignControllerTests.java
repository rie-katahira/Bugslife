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
import com.example.enums.DiscountType;
import com.example.model.Campaign;
import com.example.service.CampaignService;

/**
 * CampaignControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class CampaignControllerTests {
	@Autowired
	private CampaignService campaignService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/campaigns"))
				.andExpect(status().isOk())
				.andExpect(view().name("campaign/index"))
				.andExpect(model().attributeExists("listCampaign"));
	}

	/**
	 * get showのテスト
	 */
	@Test
	public void getShowTest(@Autowired MockMvc mvc) throws Exception {
		Campaign campaign = new Campaign();
		campaign.setName("test");
		campaign.setCode("42");
		campaign.setDiscountType(DiscountType.valueOf(1));
		campaign.setFromDate("2021-01-01");
		campaign.setToDate("2021-01-01");
		campaign.setDescription("test");

		campaignService.save(campaign);
		mvc.perform(MockMvcRequestBuilders.get("/campaigns/" + campaign.getId()))
				.andExpect(status().isOk())
				.andExpect(view().name("campaign/show"))
				.andExpect(model().attributeExists("campaign"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/campaigns/new"))
				.andExpect(status().isOk())
				.andExpect(view().name("campaign/form"))
				.andExpect(model().attributeExists("campaign"));
	}

	/**
	 * post create 失敗 テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/campaigns").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/campaigns"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(
				MockMvcRequestBuilders.post("/campaigns")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("name", "test")
						.param("code", "42")
						.param("discountType", "A")
						.param("fromDate", "2021-01-01")
						.param("toDate", "2021-01-01")
						.param("description", "test"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("/campaigns/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class,
				() -> mvc.perform(MockMvcRequestBuilders.get("/campaigns/999/edit")));
	}

	/**
	 * get update 成功テスト
	 */
	@Test
	public void getUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Campaign campaign = new Campaign();
		campaign.setName("test");
		campaign.setCode("42");
		campaign.setDiscountType(DiscountType.valueOf(1));
		campaign.setFromDate("2021-01-01");
		campaign.setToDate("2021-01-01");
		campaign.setDescription("test");
		campaignService.save(campaign);

		mvc.perform(MockMvcRequestBuilders.get("/campaigns/" + campaign.getId() + "/edit"))
				.andExpect(status().isOk())
				.andExpect(view().name("campaign/form"))
				.andExpect(model().attribute("campaign", SamePropertyValuesAs.samePropertyValuesAs(campaign)));
	}

	/**
	 * put update 失敗 テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.put("/campaigns").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/campaigns"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * put update 成功 テスト
	 */
	@Test
	public void putUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Campaign campaign = new Campaign();
		campaign.setName("test");
		campaign.setCode("42");
		campaign.setDiscountType(DiscountType.valueOf(1));
		campaign.setFromDate("2021-01-01");
		campaign.setToDate("2021-01-01");
		campaign.setDescription("test");
		campaignService.save(campaign);

		mvc.perform(
				MockMvcRequestBuilders.put("/campaigns")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("id", campaign.getId().toString())
						.param("name", "test2")
						.param("code", "43")
						.param("discountType", "A")
						.param("fromDate", "2021-01-01")
						.param("toDate", "2021-01-01")
						.param("description", "test2"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/campaigns/" + campaign.getId()))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<Campaign> campaign2 = campaignService.findOne(campaign.getId());
		Assertions.assertEquals("test2", campaign2.get().getName());
		Assertions.assertEquals("43", campaign2.get().getCode());
		Assertions.assertEquals("A", campaign2.get().getDiscountType());
		Assertions.assertEquals("2021-01-01", campaign2.get().getFromDate());
		Assertions.assertEquals("2021-01-01", campaign2.get().getToDate());
		Assertions.assertEquals("pass", campaign2.get().getStatus());
		Assertions.assertEquals("test2", campaign2.get().getDescription());

	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc
				.perform(MockMvcRequestBuilders.delete("/campaigns/999")
						.with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	/**
	 * delete 成功 テスト
	 */
	@Test
	public void deleteValidTest(@Autowired MockMvc mvc) throws Exception {
		Campaign campaign = new Campaign();
		campaign.setName("test");
		campaign.setCode("42");
		campaign.setDiscountType(DiscountType.valueOf(1));
		campaign.setFromDate("2021-01-01");
		campaign.setToDate("2021-01-01");
		campaign.setDescription("test");
		campaignService.save(campaign);

		mvc.perform(
				MockMvcRequestBuilders.delete("/campaigns/" + campaign.getId())
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/campaigns"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<Campaign> campaign2 = campaignService.findOne(campaign.getId());
		Assertions.assertFalse(campaign2.isPresent());
	}

}
