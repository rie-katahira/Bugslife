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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.constants.Message;
import com.example.model.App;
import com.example.service.AppService;
import com.example.utils.CheckUtil;

@Controller
@RequestMapping("/apps")
public class AppController {

	@Autowired
	private AppService appService;

	@GetMapping
	public String index(Model model) {
		List<App> all = appService.findAll();
		model.addAttribute("listApp", all);
		return "app/index";
	}

	@GetMapping("/{id}")
	public String show(Model model, @PathVariable("id") Long id) {
		if (id != null) {
			Optional<App> app = appService.findOne(id);
			model.addAttribute("app", app.get());
		}
		return "app/show";
	}

	@GetMapping(value = "/new")
	public String create(Model model, @ModelAttribute App entity) {
		model.addAttribute("app", entity);
		return "app/form";
	}

	@PostMapping
	public String create(@Validated @ModelAttribute App entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		App app = null;
		try {
			// descriptionは2000文字まで
			if (!CheckUtil.checkDescriptionLength(entity.getDescription())) {
				// NG
				redirectAttributes.addFlashAttribute("error", Message.MSG_VALIDATE_ERROR);
				return "redirect:/apps";
			}

			app = appService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_INSERT);
			return "redirect:/apps/" + app.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/apps";
		}
	}

	@GetMapping("/{id}/edit")
	public String update(Model model, @PathVariable("id") Long id) {
		try {
			if (id != null) {
				Optional<App> entity = appService.findOne(id);
				model.addAttribute("app", entity.get());
			}
		} catch (Exception e) {
			throw new ServiceException(e.getMessage());
		}
		return "app/form";
	}

	@PutMapping
	public String update(@Validated @ModelAttribute App entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		App app = null;
		try {
			// descriptionは2000文字まで
			if (!CheckUtil.checkDescriptionLength(entity.getDescription())) {
				// NG
				redirectAttributes.addFlashAttribute("error", Message.MSG_VALIDATE_ERROR);
				return "redirect:/apps";
			}

			app = appService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_UPDATE);
			return "redirect:/apps/" + app.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/apps";
		}
	}

	@DeleteMapping("/{id}")
	public String delete(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
		try {
			if (id != null) {
				Optional<App> entity = appService.findOne(id);
				appService.delete(entity.get());
				redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_DELETE);
			}
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			throw new ServiceException(e.getMessage());
		}
		return "redirect:/apps";
	}
}
