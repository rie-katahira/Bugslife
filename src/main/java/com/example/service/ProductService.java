package com.example.service;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.example.model.Category;
import com.example.model.CategoryProduct;
import com.example.model.Product;
import com.example.repository.CategoryProductRepository;
import com.example.repository.ProductRepository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Join;
import jakarta.persistence.criteria.JoinType;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;

import com.example.entity.ProductWithCategoryName;
import com.example.form.ProductForm;
import com.example.form.ProductSearchForm;
import org.springframework.transaction.annotation.Transactional;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class ProductService {

	@PersistenceContext
	private EntityManager entityManager;

	@Autowired
	private ProductRepository productRepository;

	@Autowired
	private CategoryProductRepository categoryProductRepository;

	public List<Product> findAll() {
		return productRepository.findAll();
	}

	public Optional<Product> findOne(Long id) {
		return productRepository.findById(id);
	}

	@Transactional(readOnly = false)
	public Product save(Product entity) {
		return productRepository.save(entity);
	}

	@Transactional(readOnly = false)
	public void delete(Product entity) {
		productRepository.delete(entity);
	}

	// 指定された検索条件に一致するエンティティを検索する
	public List<ProductWithCategoryName> search(Long shopId, ProductSearchForm form) {
		final CriteriaBuilder builder = entityManager.getCriteriaBuilder();
		final CriteriaQuery<ProductWithCategoryName> query = builder.createQuery(ProductWithCategoryName.class);
		final Root<Product> root = query.from(Product.class);

		Join<Product, CategoryProduct> categoryProductJoin = root.joinList("categoryProducts", JoinType.LEFT);
		Join<CategoryProduct, Category> categoryJoin = categoryProductJoin.join("category", JoinType.LEFT);

		query.multiselect(
				root.get("id"),
				root.get("code"),
				root.get("name"),
				root.get("weight"),
				root.get("height"),
				root.get("price"),
				builder.coalesce(
						builder.function("GROUP_CONCAT", String.class, categoryJoin.get("name"), builder.literal(", ")),
						"").alias("categoryName"))
				.groupBy(root.get("id"));

		// 初期条件（shopId）を設定
		Predicate predicates = builder.equal(root.get("shopId"), shopId);

		// formの値を元に検索条件を設定する
		if (!StringUtils.isEmpty(form.getName())) {
			// name で部分一致検索
			predicates = builder.and(predicates, builder.like(root.get("name"), "%" + form.getName() + "%"));
		}

		if (!StringUtils.isEmpty(form.getCode())) {
			// code で部分一致検索
			predicates = builder.and(predicates, builder.like(root.get("code"), "%" + form.getCode() + "%"));
		}

		if (form.getCategories() != null && form.getCategories().size() > 0) {
			// 渡されたカテゴリーIDのリストを元にサブクエリを作成
			List<Predicate> categoryPredicates = new ArrayList<>();
			for (Long categoryId : form.getCategories()) {
				Subquery<Long> subquery = query.subquery(Long.class);
				Root<CategoryProduct> subqueryRoot = subquery.from(CategoryProduct.class);
				subquery.select(subqueryRoot.get("product").get("id"));
				subquery.where(subqueryRoot.get("category").get("id").in(categoryId));
				categoryPredicates.add(builder.in(root.get("id")).value(subquery));
			}
			// 作成したサブクエリを元に検索条件をANDで設定
			predicates = builder.and(predicates, builder.and(categoryPredicates.toArray(new Predicate[0])));
		}

		// weight で範囲検索
		if (form.getWeight1() != null && form.getWeight2() != null) {
			predicates = builder.and(predicates,
					builder.between(root.get("weight"), form.getWeight1(), form.getWeight2()));
		} else if (form.getWeight1() != null) {
			predicates = builder.and(predicates, builder.greaterThanOrEqualTo(root.get("weight"), form.getWeight1()));
		} else if (form.getWeight2() != null) {
			predicates = builder.and(predicates, builder.lessThanOrEqualTo(root.get("weight"), form.getWeight2()));
		}

		// height で範囲検索
		if (form.getHeight1() != null && form.getHeight2() != null) {
			predicates = builder.and(predicates,
					builder.between(root.get("height"), form.getHeight1(), form.getHeight2()));
		} else if (form.getHeight1() != null) {
			predicates = builder.and(predicates, builder.greaterThanOrEqualTo(root.get("height"), form.getHeight1()));
		} else if (form.getHeight2() != null) {
			predicates = builder.and(predicates, builder.lessThanOrEqualTo(root.get("height"), form.getHeight2()));
		}

		// price で範囲検索
		if (form.getPrice1() != null && form.getPrice2() != null) {
			predicates = builder.and(predicates,
					builder.between(root.get("price"), form.getPrice1(), form.getPrice2()));
		} else if (form.getPrice1() != null) {
			predicates = builder.and(predicates, builder.greaterThanOrEqualTo(root.get("price"), form.getPrice1()));
		} else if (form.getPrice2() != null) {
			predicates = builder.and(predicates, builder.lessThanOrEqualTo(root.get("price"), form.getPrice2()));
		}

		query.where(predicates);

		return entityManager.createQuery(query).getResultList();
	}

	/**
	 * ProductFormの内容を元に商品情報を保存する
	 * 
	 * @param entity
	 * @return
	 */
	@Transactional(readOnly = false)
	public Product save(ProductForm entity) {
		// 紐づくカテゴリを事前に取得
		List<CategoryProduct> categoryProducts = entity.getId() != null
				? categoryProductRepository.findByProductId(entity.getId())
				: new ArrayList<>();

		Product product = new Product(entity);
		productRepository.save(product);

		// 未処理のカテゴリーIDのリスト
		List<Long> categoryIds = entity.getCategoryIds();
		// カテゴリの紐付け解除
		for (CategoryProduct categoryProduct : categoryProducts) {
			// 紐づくカテゴリーIDが更新後のカテゴリーIDに含まれていない場合は削除
			if (!categoryIds.contains(categoryProduct.getCategoryId())) {
				categoryProductRepository.delete(categoryProduct);
			}
			// 処理が終わったものをリストから削除
			categoryIds.remove(categoryProduct.getCategoryId());
		}
		// カテゴリの紐付け登録
		for (Long categoryId : categoryIds) {
			categoryProductRepository.save(new CategoryProduct(categoryId, product.getId()));
		}

		return product;
	}
}
