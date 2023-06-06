package com.example.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.model.DeletedUser;

public interface DeletedUserRepository extends JpaRepository<DeletedUser, Long> {

}
