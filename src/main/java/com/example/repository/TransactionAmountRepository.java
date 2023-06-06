package com.example.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.model.Company;
import com.example.model.TransactionAmount;

public interface TransactionAmountRepository extends JpaRepository<TransactionAmount, Long> {
	List<TransactionAmount> findByCompany(Company company);
}
