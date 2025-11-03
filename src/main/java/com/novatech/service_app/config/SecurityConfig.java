package com.novatech.service_app.config;

import com.novatech.service_app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy; // ✅ IMPORT
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl; // ✅ IMPORT
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler; // ✅ IMPORT
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserService userService;

    @Autowired
    private PasswordEncoder passwordEncoder; // ✅ comes from PasswordConfig.java

    /**
     * ✅ Custom Authentication Provider using UserService.
     */
    @Bean
    public DaoAuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }

    /**
     * ✅ Authentication Manager for Spring Security.
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
        return authConfig.getAuthenticationManager();
    }

    /**
     * ✅ NEW: Defines the Role Hierarchy
     * This tells Spring that SUPER_ADMIN is superior to ADMIN, and ADMIN is superior to USER.
     */
    @Bean
    public RoleHierarchy roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        String hierarchy = "ROLE_SUPER_ADMIN > ROLE_ADMIN \n ROLE_ADMIN > ROLE_USER";
        roleHierarchy.setHierarchy(hierarchy);
        return roleHierarchy;
    }

    /**
     * ✅ NEW: Applies the Role Hierarchy to the security expression handler.
     */
    @Bean
    public DefaultWebSecurityExpressionHandler webSecurityExpressionHandler() {
        DefaultWebSecurityExpressionHandler expressionHandler = new DefaultWebSecurityExpressionHandler();
        expressionHandler.setRoleHierarchy(roleHierarchy());
        return expressionHandler;
    }

    /**
     * ✅ Custom success handler:
     * Redirects admin → /admin/dashboard
     * Redirects user → /home
     * ✅ UPDATED: Now includes ROLE_SUPER_ADMIN
     */
    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return (request, response, authentication) -> {
            boolean isAdmin = authentication.getAuthorities().stream()
                    .anyMatch(auth -> auth.getAuthority().equals("ROLE_ADMIN") ||
                            auth.getAuthority().equals("ROLE_SUPER_ADMIN")); // ✅ CHECK FOR BOTH

            if (isAdmin) {
                response.sendRedirect("/admin/dashboard");
            } else {
                response.sendRedirect("/home");
            }
        };
    }

    /**
     * ✅ Main Security Configuration:
     * Handles route access, login/logout, and exception handling.
     */
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // CSRF configuration: enabled but ignores SSO callbacks
                .csrf(csrf -> csrf
                        .ignoringRequestMatchers("/sso/**") // ✅ Allow external SSO providers
                )

                // Authorization setup
                .authorizeHttpRequests(auth -> auth
                        // Public pages (no authentication required)
                        .requestMatchers(
                                "/", "/login", "/signup", "/register",
                                "/sso/**", "/error",
                                "/css/**", "/js/**", "/images/**", "/favicon.ico"
                        ).permitAll()

                        // ✅ UPDATED: Admin-only pages (requires ROLE_ADMIN or ROLE_SUPER_ADMIN)
                        .requestMatchers("/admin/**").hasAnyRole("ADMIN", "SUPER_ADMIN")

                        // All other pages require authentication
                        .anyRequest().authenticated()
                )

                // Form login configuration
                .formLogin(form -> form
                        .loginPage("/login")
                        .loginProcessingUrl("/login")
                        .successHandler(customSuccessHandler())
                        .failureUrl("/login?error=true")
                        .usernameParameter("email")
                        .passwordParameter("password")
                        .permitAll()
                )

                // Logout configuration
                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout=true")
                        .invalidateHttpSession(true)
                        .deleteCookies("JSESSIONID")
                        .permitAll()
                )

                // Access denied handler
                .exceptionHandling(ex -> ex
                        .accessDeniedPage("/login?error=access-denied")
                );

        http.authenticationProvider(authenticationProvider());
        return http.build();
    }
}