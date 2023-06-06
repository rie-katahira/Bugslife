package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.model.OrderProduct;

public interface OrderProductRepository extends JpaRepository<OrderProduct, Long> {}
