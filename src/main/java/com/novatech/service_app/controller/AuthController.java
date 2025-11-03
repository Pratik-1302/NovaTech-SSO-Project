package com.novatech.service_app.controller;

import com.novatech.service_app.dto.SignupRequest;
import com.novatech.service_app.service.SsoManagementService;
import com.novatech.service_app.service.UserService;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AuthController {

    private static final Logger logger = LoggerFactory.getLogger(AuthController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private SsoManagementService ssoManagementService;

    // ===================== LOGIN PAGE =====================
    @GetMapping("/login")
    public String loginPage(
            @RequestParam(value = "error", required = false) String error,
            @RequestParam(value = "success", required = false) String success,
            Model model) {

        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            logger.info("User already authenticated, redirecting to /home");
            return "redirect:/home";
        }

        logger.info("=== LOGIN PAGE ACCESSED ===");
        logger.info("Error param: {}, Success param: {}", error, success);

        if (error != null) {
            model.addAttribute("error", "Invalid email or password");
        }

        if (success != null) {
            model.addAttribute("success", "Registration successful! Please login.");
        }

        // ✅ NEW: Check database for enabled SSO options
        boolean jwtEnabled = ssoManagementService.isJwtEnabled();
        boolean oidcEnabled = ssoManagementService.isOidcEnabled();
        boolean samlEnabled = ssoManagementService.isSamlEnabled();

        model.addAttribute("jwtEnabled", jwtEnabled);
        model.addAttribute("oidcEnabled", oidcEnabled);
        model.addAttribute("samlEnabled", samlEnabled);

        // For backward compatibility (if any old code checks this)
        boolean anySsoEnabled = jwtEnabled || oidcEnabled || samlEnabled;
        model.addAttribute("ssoEnabled", anySsoEnabled);

        logger.info("SSO Status - JWT: {}, OIDC: {}, SAML: {}", jwtEnabled, oidcEnabled, samlEnabled);

        return "login";
    }

    // ===================== SIGNUP PAGE =====================
    @GetMapping("/signup")
    public String signupPage(Model model) {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth != null && auth.isAuthenticated() && !"anonymousUser".equals(auth.getPrincipal())) {
            logger.info("Authenticated user tried to access signup — redirecting to /home");
            return "redirect:/home";
        }

        logger.info("=== SIGNUP PAGE ACCESSED ===");
        model.addAttribute("signupRequest", new SignupRequest());
        return "signup";
    }

    // ===================== SIGNUP FORM HANDLER =====================
    @PostMapping("/signup")
    public String registerUser(
            @Valid @ModelAttribute("signupRequest") SignupRequest signupRequest,
            BindingResult result,
            Model model) {

        logger.info("=== SIGNUP FORM SUBMITTED ===");
        logger.info("Full Name: {}, Email: {}", signupRequest.getFullName(), signupRequest.getEmail());

        // Validation errors
        if (result.hasErrors()) {
            logger.error("Validation errors: {}", result.getAllErrors());
            return "signup";
        }

        // Password match check
        if (!signupRequest.getPassword().equals(signupRequest.getConfirmPassword())) {
            logger.warn("Passwords do not match for email: {}", signupRequest.getEmail());
            model.addAttribute("error", "Passwords do not match");
            return "signup";
        }

        // Check existing email
        if (userService.emailExists(signupRequest.getEmail())) {
            logger.warn("Email already registered: {}", signupRequest.getEmail());
            model.addAttribute("error", "Email already registered");
            return "signup";
        }

        try {
            // Register user
            userService.registerUser(
                    signupRequest.getFullName(),
                    signupRequest.getEmail(),
                    signupRequest.getPassword()
            );
            logger.info("User registered successfully: {}", signupRequest.getEmail());
            return "redirect:/login?success=true";

        } catch (Exception e) {
            logger.error("Error during registration: {}", e.getMessage(), e);
            model.addAttribute("error", "Registration failed: " + e.getMessage());
            return "signup";
        }
    }
}
//working-version