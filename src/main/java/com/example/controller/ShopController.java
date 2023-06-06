package com.example.controller;

import java.util.List;
import java.util.Optional;

import org.hibernate.service.spi.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.constants.Message;
import com.example.model.Shop;
import com.example.service.ShopService;

@Controller
@RequestMapping("/shops")
public class ShopController {

	@Autowired
	private ShopService shopService;

	@GetMapping
	public String index(Model model, @RequestParam(name = "name", required = false) Optional<String> name) {
		Shop probe = new Shop();
		if (name.isPresent()) {
			probe.setName(name.get());
		}
		List<Shop> shops = shopService.findAll(probe);
		model.addAttribute("listShop", shops);
		model.addAttribute("name", name.isPresent() ? name.get() : null);
		return "shop/index";
	}

	@GetMapping("/{id}")
	public String show(Model model, @PathVariable("id") Long id) {
		if (id != null) {
			Optional<Shop> shop = shopService.findOne(id);
			model.addAttribute("shop", shop.get());
		}
		return "shop/show";
	}

	@GetMapping(value = "/new")
	public String create(Model model, @ModelAttribute Shop entity) {
		model.addAttribute("shop", entity);
		return "shop/form";
	}

	@PostMapping
	public String create(Model model, @Validated @ModelAttribute Shop entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		// バリデーションチェック
		if (result.hasErrors()) {
			model.addAttribute("shop", entity);
			return "shop/form";
		}

		Shop shop = null;
		try {
			shop = shopService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_INSERT);
			return "redirect:/shops/" + shop.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/shops";
		}
	}

	@GetMapping("/{id}/edit")
	public String update(Model model, @PathVariable("id") Long id) {
		try {
			if (id != null) {
				Optional<Shop> entity = shopService.findOne(id);
				model.addAttribute("shop", entity.get());
			}
		} catch (Exception e) {
			throw new ServiceException(e.getMessage());
		}
		return "shop/form";
	}

	@PutMapping
	public String update(Model model, @Validated @ModelAttribute Shop entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		// バリデーションチェック
		if (result.hasErrors()) {
			model.addAttribute("shop", entity);
			return "shop/form";
		}

		Shop shop = null;
		try {
			shop = shopService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_UPDATE);
			return "redirect:/shops/" + shop.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/shops";
		}
	}

	@DeleteMapping("/{id}")
	public String delete(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
		try {
			if (id != null) {
				Optional<Shop> entity = shopService.findOne(id);
				shopService.delete(entity.get());
				redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_DELETE);
			}
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			throw new ServiceException(e.getMessage());
		}
		return "redirect:/shops";
	}
}
