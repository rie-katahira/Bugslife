package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.model.App;

public interface AppRepository extends JpaRepository<App, Long> {}
