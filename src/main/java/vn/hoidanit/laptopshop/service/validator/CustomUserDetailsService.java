package vn.hoidanit.laptopshop.service.validator;

import java.util.Collections;

import org.hibernate.usertype.UserVersionType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User;

import vn.hoidanit.laptopshop.service.UserService;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserService userService;

    public CustomUserDetailsService(UserService userService) {
        this.userService = userService;
    }

    // username == email
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        vn.hoidanit.laptopshop.domain.User user = this.userService.getUserByEmail(username);
        if (user == null) {
            throw new UsernameNotFoundException("User not found");
        }
        // auto get role
        return new User(
                user.getEmail(),
                user.getPassword(),
                Collections.singletonList(new SimpleGrantedAuthority("ROLE_" +  user.getRole().getName())));
    }

}
