package com.novatech.service_app.service;

import com.novatech.service_app.entity.User;
import com.novatech.service_app.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException; // Keep this import
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

// ❌ We no longer need 'java.security.Principal'
import java.util.List;

/**
 * ✅ Handles:
 * - Authentication and registration
 * - Admin CRUD operations for users
 * - SSO configuration is now managed via SsoManagementService
 */
@Service
public class UserService implements UserDetailsService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    // ======================================================
    //          SPRING SECURITY AUTHENTICATION
    // ======================================================

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getEmail())
                .password(user.getPasswordHash())
                .roles(user.getRole().replace("ROLE_", ""))
                .build();
    }

    // ======================================================
    //                   USER MANAGEMENT
    // ======================================================

    @Transactional(readOnly = true)
    public User findByEmail(String email) {
        return userRepository.findByEmail(email).orElse(null);
    }

    @Transactional(readOnly = true)
    public List<User> getAllUsers() {
        // ✅ We still sort by ID
        return userRepository.findAllByOrderByIdAsc();
    }

    @Transactional(readOnly = true)
    public boolean emailExists(String email) {
        return userRepository.existsByEmail(email);
    }

    @Transactional
    public User registerUser(String fullName, String email, String password) {
        // ... (this method is unchanged) ...
        if (emailExists(email)) {
            throw new RuntimeException("User already exists with email: " + email);
        }

        User user = new User();
        user.setFullName(fullName);
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(password));
        user.setRole("ROLE_USER");
        return userRepository.save(user);
    }

    @Transactional
    public void createUserWithPassword(User user, String password) {
        // ... (this method is unchanged) ...
        if (userRepository.findByEmail(user.getEmail()).isPresent()) {
            throw new RuntimeException("User already exists with this email!");
        }

        user.setPasswordHash(passwordEncoder.encode(password));

        if (user.getRole() == null || user.getRole().isEmpty()) {
            user.setRole("ROLE_USER");
        }

        userRepository.save(user);
    }

    /**
     * ✅ UPDATED: Update user details (admin function)
     * Simplified: Now only checks the target user's role.
     */
    @Transactional
    public void updateUserDetails(Long id, String fullName, String password, String role) {

        User targetUser = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        // ✅ THE NEW SECURITY CHECK:
        // Is the target user a SUPER_ADMIN?
        if (targetUser.getRole().equals("ROLE_SUPER_ADMIN")) {
            // If yes, block them.
            throw new AccessDeniedException("Access Denied: The Super Admin account cannot be modified.");
        }

        // Is someone trying to *promote* another user to Super Admin?
        if (role.equals("ROLE_SUPER_ADMIN")) {
            throw new AccessDeniedException("Access Denied: A new Super Admin cannot be created.");
        }

        // --- Security check passed, proceed with update ---

        targetUser.setFullName(fullName);
        targetUser.setRole(role);

        if (password != null && !password.isEmpty()) {
            targetUser.setPasswordHash(passwordEncoder.encode(password));
        }

        userRepository.save(targetUser);
    }

    /**
     * ✅ UPDATED: Delete user by ID (admin function)
     * Simplified: Now only checks the target user's role.
     */
    @Transactional
    public void deleteUserById(Long id) {

        User targetUser = userRepository.findById(id)
                .orElseThrow(() -> new RuntimeException("User not found with ID: " + id));

        // ✅ THE NEW SECURITY CHECK:
        if (targetUser.getRole().equals("ROLE_SUPER_ADMIN")) {
            throw new AccessDeniedException("Access Denied: The Super Admin account cannot be deleted.");
        }

        // --- Security check passed, proceed with deletion ---
        userRepository.deleteById(id);
    }
}

