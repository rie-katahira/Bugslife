package com.example.service;

import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.example.model.CategoryProduct;
import com.example.repository.CategoryProductRepository;

@Service
@Transactional(readOnly = true)
public class CategoryProductService {

	@Autowired
	private CategoryProductRepository categoryProductRepository;

	public List<CategoryProduct> findAll() {
		return categoryProductRepository.findAll();
	}

	public Optional<CategoryProduct> findOne(Long id) {
		return categoryProductRepository.findById(id);
	}

	@Transactional(readOnly = false)
	public CategoryProduct save(CategoryProduct entity) {
		return categoryProductRepository.save(entity);
	}

	@Transactional(readOnly = false)
	public void delete(CategoryProduct entity) {
		categoryProductRepository.delete(entity);
	}

	// 対象の商品IDに紐づくCategoryProductを取得
	public List<CategoryProduct> findByProductId(Long productId) {
		return categoryProductRepository.findByProductId(productId);
	}
}
