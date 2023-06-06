package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.model.Order;

public interface OrderRepository extends JpaRepository<Order, Long> {}
