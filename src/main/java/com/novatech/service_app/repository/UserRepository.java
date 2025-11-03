package com.novatech.service_app.repository;

import com.novatech.service_app.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;
import java.util.List;
import java.util.Optional;

/**
 * Repository interface for managing User entities.
 * Provides CRUD operations and custom lookups.
 */
@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    /**
     * Find user by email (used for login, registration, and SSO validation).
     */
    Optional<User> findByEmail(String email);

    /**
     * Check if a user exists by email (used in signup validation).
     */
    boolean existsByEmail(String email);

    /**
     * Find all users by role (for admin dashboard filtering).
     */
    List<User> findByRole(String role);

    /**
     * ✅ THIS IS THE FIX
     * Finds all users and automatically sorts them by the 'id' field in ascending order.
     */
    List<User> findAllByOrderByIdAsc();
}
