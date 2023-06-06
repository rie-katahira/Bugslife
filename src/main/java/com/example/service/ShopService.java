package com.example.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Example;
import org.springframework.stereotype.Service;
import com.example.model.Shop;
import com.example.repository.ShopRepository;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Service
@Transactional(readOnly = true)
public class ShopService {

	@Autowired
	private ShopRepository shopRepository;

	public List<Shop> findAll() {
		return shopRepository.findAll();
	}

	public List<Shop> findAll(Shop probe) {
		return shopRepository.findAll(Example.of(probe));
	}

	public Optional<Shop> findOne(Long id) {
		return shopRepository.findById(id);
	}

	@Transactional(readOnly = false)
	public Shop save(Shop entity) {
		return shopRepository.save(entity);
	}

	@Transactional(readOnly = false)
	public void delete(Shop entity) {
		shopRepository.delete(entity);
	}

}
