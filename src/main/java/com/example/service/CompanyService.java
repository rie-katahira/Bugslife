package com.example.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.model.Company;
import com.example.repository.CompanyRepository;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class CompanyService {

	@Autowired
	private CompanyRepository companyRepository;

	public List<Company> findAll() {
		return companyRepository.findAll();
	}

	public Optional<Company> findOne(Long id) {
		return companyRepository.findById(id);
	}

	@Transactional(readOnly = false)
	public Company save(Company entity) {
		return companyRepository.save(entity);
	}

	@Transactional(readOnly = false)
	public void delete(Company entity) {
		companyRepository.delete(entity);
	}

}
