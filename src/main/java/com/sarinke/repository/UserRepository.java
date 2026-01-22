package com.sarinke.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.sarinke.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
	Optional<User> findByUsername(String username);
}
