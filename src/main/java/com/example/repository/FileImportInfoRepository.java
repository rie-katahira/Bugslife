package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.model.FileImportInfo;

public interface FileImportInfoRepository extends JpaRepository<FileImportInfo, Long> {}