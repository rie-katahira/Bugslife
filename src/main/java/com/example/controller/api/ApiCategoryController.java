package com.example.controller.api;

import com.example.service.CategoryService;
import com.example.model.Category;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Optional;
import java.util.Map;

@RestController
@RequestMapping("/api/categories")
public class ApiCategoryController {

	@Autowired
	private CategoryService categoryService;

	@GetMapping("/all")
	List<Category> findAll() {
		return categoryService.findAll();
	}

	@GetMapping("/{id}")
	Optional<Category> findOne(@PathVariable("id") Long id) {
		Optional<Category> category = categoryService.findOne(id);
		return category;
	}

	@PostMapping("/{id}/updateCategoryProduct")
	public ResponseEntity<String> deleteInsertCategoryProduct(@PathVariable("id") Long categoryId,
			@RequestBody Map<String, List<Long>> request) {
		List<Long> productIds = request.get("productIds");
		boolean result = categoryService.deleteInsertCategoryProduct(categoryId, productIds);
		if (result) {
			return ResponseEntity.ok("カテゴリーと商品の紐付設定更新を完了しました。");
		} else {
			return ResponseEntity.badRequest().body("カテゴリーと商品の紐付設定更新に失敗しました。");
		}
	}

}
