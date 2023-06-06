package com.example.controller;

import java.util.List;
import java.util.Optional;

import org.hibernate.service.spi.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.constants.Message;
import com.example.form.UserSearchForm;
import com.example.model.User;
import com.example.service.UserService;

@Controller
@RequestMapping("/users")
public class UserController {

	@Autowired
	private UserService userService;

	@GetMapping
	public String index(Model model, @ModelAttribute UserSearchForm request, Authentication authentication) {
		boolean isAdmin = userService.isAdmin(authentication);
		List<User> listUser = userService.search(request, isAdmin);
		model.addAttribute("request", request);
		model.addAttribute("listUser", listUser);
		return "user/index";
	}

	@GetMapping("/{id}")
	public String show(Model model, @PathVariable("id") Long id) {
		if (id != null) {
			Optional<User> user = userService.findOne(id);
			model.addAttribute("user", user.get());
		}
		return "user/show";
	}

	@GetMapping(value = "/new")
	public String create(Model model, @ModelAttribute User entity, Authentication authentication) {
		boolean isAdmin = userService.isAdmin(authentication);
		model.addAttribute("isAdmin", isAdmin);
		model.addAttribute("roles", User.Roles.values());
		model.addAttribute("user", entity);
		return "user/form";
	}

	@PostMapping
	public String create(@Validated @ModelAttribute User entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		User user = null;
		try {
			user = userService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_INSERT);
			return "redirect:/users/" + user.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/users";
		}
	}

	@GetMapping("/{id}/edit")
	public String update(Model model, @PathVariable("id") Long id, Authentication authentication) {
		try {
			boolean isAdmin = userService.isAdmin(authentication);
			model.addAttribute("isAdmin", isAdmin);
			model.addAttribute("roles", User.Roles.values());
			if (id != null) {
				Optional<User> entity = userService.findOne(id);
				model.addAttribute("user", entity.get());
			}
		} catch (Exception e) {
			throw new ServiceException(e.getMessage());
		}
		return "user/form";
	}

	@PutMapping
	public String update(@Validated @ModelAttribute User entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		User user = null;
		try {
			user = userService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_UPDATE);
			return "redirect:/users/" + user.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/users";
		}
	}

	@DeleteMapping("/{id}")
	public String delete(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
		try {
			if (id != null) {
				Optional<User> entity = userService.findOne(id);
				userService.delete(entity.get());
				redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_DELETE);
			}
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			throw new ServiceException(e.getMessage());
		}
		return "redirect:/users";
	}
}
