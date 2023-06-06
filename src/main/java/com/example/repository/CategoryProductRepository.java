package com.example.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.model.CategoryProduct;

public interface CategoryProductRepository extends JpaRepository<CategoryProduct, Long> {
	void deleteByCategoryId(Long categoryId);

	// productIdで検索
	List<CategoryProduct> findByProductId(Long productId);
}
