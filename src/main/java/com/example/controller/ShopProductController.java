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
import com.example.constants.TaxType;
import com.example.entity.ProductWithCategoryName;
import com.example.form.ProductForm;
import com.example.form.ProductSearchForm;
import com.example.model.Category;
import com.example.model.Product;
import com.example.service.CategoryService;
import com.example.service.ProductService;

@Controller
@RequestMapping("/shops/{shopId}/products")
public class ShopProductController {

	@Autowired
	private ProductService productService;

	@Autowired
	private CategoryService categoryService;


	@GetMapping
	public String index(Model model, @PathVariable("shopId") Long shopId, @ModelAttribute ProductSearchForm request) {
		List<ProductWithCategoryName> all = productService.search(shopId, request);
		List<Category> categories = categoryService.findAll();
		model.addAttribute("listProduct", all);
		model.addAttribute("categories", categories);
		model.addAttribute("request", request);
		model.addAttribute("shopId", shopId);
		return "shop_product/index";
	}

	@GetMapping("/{id}")
	public String show(Model model, @PathVariable("shopId") Long shopId, @PathVariable("id") Long id) {
		if (id != null) {
			Optional<Product> product = productService.findOne(id);
			List<Category> categories = categoryService.findAll();
			model.addAttribute("categories", categories);
			model.addAttribute("product", product.get());
			model.addAttribute("tax", TaxType.get(product.get().getTaxType()));
			model.addAttribute("shopId", shopId);
		}
		return "shop_product/show";
	}

	@GetMapping(value = "/new")
	public String create(Model model, @PathVariable("shopId") Long shopId, @ModelAttribute ProductForm productForm) {
		List<Category> categories = categoryService.findAll();
		model.addAttribute("categories", categories);
		model.addAttribute("productForm", productForm);
		model.addAttribute("shopId", shopId);
		return "shop_product/form";
	}

	@PostMapping
	public String create(Model model, @PathVariable("shopId") Long shopId, @Validated @ModelAttribute ProductForm productForm,
			BindingResult result, RedirectAttributes redirectAttributes) {
		// バリデーションチェック
		if (result.hasErrors()) {
			List<Category> categories = categoryService.findAll();
			model.addAttribute("categories", categories);
			model.addAttribute("productForm", productForm);
			model.addAttribute("shopId", shopId);
			return "shop_product/form";
		}

		Product product = null;
		try {
			product = productService.save(productForm);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_INSERT);
			return "redirect:/shops/{shopId}/products/" + product.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/shops/{shopId}/products";
		}
	}

	@GetMapping("/{id}/edit")
	public String update(Model model, @PathVariable("shopId") Long shopId, @PathVariable("id") Long id) {
		try {
			if (id != null) {
				Optional<Product> entity = productService.findOne(id);
				List<Category> categories = categoryService.findAll();
				model.addAttribute("categories", categories);
				model.addAttribute("productForm", new ProductForm(entity.get()));
				model.addAttribute("shopId", shopId);
			}
		} catch (Exception e) {
			throw new ServiceException(e.getMessage());
		}
		return "shop_product/form";
	}

	@PutMapping
	public String update(Model model, @PathVariable("shopId") Long shopId, @Validated @ModelAttribute ProductForm productForm,
			BindingResult result,RedirectAttributes redirectAttributes) {
		System.out.append(Message.MSG_ERROR, 0, 0);
		// バリデーションチェック
		if (result.hasErrors()) {
			List<Category> categories = categoryService.findAll();
			model.addAttribute("categories", categories);
			model.addAttribute("productForm", productForm);
			model.addAttribute("shopId", shopId);
			return "shop_product/form";
		}

		Product product = null;
		try {
			product = productService.save(productForm);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_UPDATE);
			return "redirect:/shops/{shopId}/products/" + product.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/shops/{shopId}/products";
		}
	}

	@DeleteMapping("/{id}")
	public String delete(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
		try {
			if (id != null) {
				Optional<Product> entity = productService.findOne(id);
				productService.delete(entity.get());
				redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_DELETE);
			}
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			throw new ServiceException(e.getMessage());
		}
		return "redirect:/shops/{shopId}/products";
	}
}
