package com.example.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.model.Campaign;

public interface CampaignRepository extends JpaRepository<Campaign, Long> {

	public Optional<Campaign> findByCode(String code);
}
