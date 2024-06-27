package vn.hoidanit.laptopshop.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.session.security.web.authentication.SpringSessionRememberMeServices;

import jakarta.servlet.DispatcherType;

@Configuration
@EnableMethodSecurity(securedEnabled = true)
public class SecurityConfiguration {

        @Bean
        public PasswordEncoder passwordEncoder() {
                return new BCryptPasswordEncoder();
        }
        // Từ version 5.8, Spring Security không dùng WebSecurityConfigurerAdapter
        // https://spring.io/blog/2022/02/21/spring-security-without-thewebsecurityconfigureradapter

        @Bean
        public DaoAuthenticationProvider authProvider(
                        PasswordEncoder passwordEncoder,
                        UserDetailsService userDetailsService) {
                DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
                authProvider.setUserDetailsService(userDetailsService);
                authProvider.setPasswordEncoder(passwordEncoder);
                authProvider.setHideUserNotFoundExceptions(false);
                return authProvider;
        }

        @Bean
        public AuthenticationSuccessHandler customSuccessHandler() {
                return new CustomSuccessHandler();
        }

        // rememberme clear session -> login +30days
        @Bean
        public SpringSessionRememberMeServices rememberMeServices() {
                SpringSessionRememberMeServices rememberMeServices = new SpringSessionRememberMeServices();
                // optionally customize
                rememberMeServices.setAlwaysRemember(true);
                return rememberMeServices;
        }

        // security v6
        @Bean
        SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
                http
                                .authorizeHttpRequests(authorize -> authorize
                                                .dispatcherTypeMatchers(DispatcherType.FORWARD,
                                                                DispatcherType.INCLUDE)
                                                .permitAll()
                                                .requestMatchers("/", "/product/**", "/login", "/register",
                                                                "/products/**",
                                                                "/client/**", "/css/**",
                                                                "/js/**",
                                                                "/images/**")
                                                .permitAll()
                                                .requestMatchers("/admin/**").hasRole("ADMIN")
                                                .anyRequest().authenticated())
                                .sessionManagement((sessionManagement) -> sessionManagement
                                                .sessionCreationPolicy(SessionCreationPolicy.ALWAYS)
                                                .invalidSessionUrl("/logout?expired")
                                                .maximumSessions(1)// bao nhieu tai khoan dang nhap cung 1 thoi gian
                                                .maxSessionsPreventsLogin(false)) // nguoi sau vao logout nguoi truoc ra
                                .rememberMe(r -> r.rememberMeServices(rememberMeServices()))
                                .formLogin(formLogin -> formLogin
                                                .loginPage("/login")
                                                .failureUrl("/login?error")
                                                .successHandler(customSuccessHandler())
                                                .permitAll())
                                .exceptionHandling(ex -> ex.accessDeniedPage("/access-deny"));
                return http.build();
        }

}
