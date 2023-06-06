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
import com.example.model.App;
import com.example.service.AppService;

/**
 * AppControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class AppControllerTests {
	private static final String TEST_IMAGE = "data:image/gif;base64,R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7";

	@Autowired
	private AppService appService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/apps")).andExpect(status().isOk()).andExpect(view().name("app/index"))
				.andExpect(model().attributeExists("listApp"));
	}

	/**
	 * get showのテスト
	 */
	@Test
	public void getShowTest(@Autowired MockMvc mvc) throws Exception {
		App app = new App();
		app.setName("test");
		app.setUrl("test");
		app.setDeveloper("test");
		app.setDescription("test");
		app.setImage(TEST_IMAGE);
		app.setActive(true);
		appService.save(app);
		mvc.perform(MockMvcRequestBuilders.get("/apps/" + app.getId())).andExpect(status().isOk())
				.andExpect(view().name("app/show")).andExpect(model().attributeExists("app"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/apps/new")).andExpect(status().isOk()).andExpect(view().name("app/form"))
				.andExpect(model().attributeExists("app"));
	}

	/**
	 * post create 失敗 テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/apps").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/apps"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/apps")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("name", "test")
				.param("url", "test")
				.param("developer", "test")
				.param("description", "test")
				.param("image", TEST_IMAGE).param("active", "true"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("/apps/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc.perform(MockMvcRequestBuilders.get("/apps/999/edit")));
	}

	/**
	 * get update 成功テスト
	 */
	@Test
	public void getUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		App app = new App();
		app.setName("test");
		app.setUrl("test");
		app.setDeveloper("test");
		app.setDescription("test");
		app.setImage(TEST_IMAGE);
		app.setActive(true);
		appService.save(app);

		mvc.perform(MockMvcRequestBuilders.get("/apps/" + app.getId() + "/edit")).andExpect(status().isOk())
				.andExpect(view().name("app/form"))
				.andExpect(model().attribute("app", SamePropertyValuesAs.samePropertyValuesAs(app)));
	}

	/**
	 * put update 失敗 テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.put("/apps").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound()).andExpect(redirectedUrl("/apps"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * put update 成功 テスト
	 */
	@Test
	public void putUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		App app = new App();
		app.setName("test");
		app.setUrl("test");
		app.setDeveloper("test");
		app.setDescription("test");
		app.setImage(TEST_IMAGE);
		app.setActive(true);
		appService.save(app);

		mvc.perform(MockMvcRequestBuilders.put("/apps")
				.with(SecurityMockMvcRequestPostProcessors.csrf())
				.param("id", app.getId().toString())
				.param("name", "test2")
				.param("url", "test2")
				.param("developer", "test2")
				.param("description", "test2")
				.param("image", TEST_IMAGE)
				.param("active", "false")).andExpect(status().isFound()).andExpect(redirectedUrl("/apps/" + app.getId()))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<App> app2 = appService.findOne(app.getId());
		Assertions.assertEquals("test2", app2.get().getName());
		Assertions.assertEquals("test2", app2.get().getUrl());
		Assertions.assertEquals("test2", app2.get().getDeveloper());
		Assertions.assertEquals("test2", app2.get().getDescription());
		Assertions.assertEquals(TEST_IMAGE, app2.get().getImage());
		Assertions.assertEquals(false, app2.get().getActive());
	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc
				.perform(MockMvcRequestBuilders.delete("/apps/999").with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	/**
	 * delete 成功 テスト
	 */
	@Test
	public void deleteValidTest(@Autowired MockMvc mvc) throws Exception {
		App app = new App();
		app.setName("test");
		app.setUrl("test");
		app.setDeveloper("test");
		app.setDescription("test");
		app.setImage(TEST_IMAGE);
		app.setActive(true);
		appService.save(app);

		mvc.perform(MockMvcRequestBuilders.delete("/apps/" + app.getId()).with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/apps")).andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<App> app2 = appService.findOne(app.getId());
		Assertions.assertFalse(app2.isPresent());
	}
}
