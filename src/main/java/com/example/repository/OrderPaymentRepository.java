package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.model.OrderPayment;

public interface OrderPaymentRepository extends JpaRepository<OrderPayment, Long> {}
