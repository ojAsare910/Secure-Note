package com.ojasare.secure_notes.security.userConfig;

import com.ojasare.secure_notes.models.AppRole;
import com.ojasare.secure_notes.models.Role;
import com.ojasare.secure_notes.models.User;
import com.ojasare.secure_notes.repository.RoleRepository;
import com.ojasare.secure_notes.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.time.LocalDate;

@Component
@Slf4j
@RequiredArgsConstructor
public class InitialUserInfo implements CommandLineRunner {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) throws Exception {
        Role userRole = roleRepository.findByRoleName(AppRole.ROLE_USER)
                .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_USER)));

        Role adminRole = roleRepository.findByRoleName(AppRole.ROLE_ADMIN)
                .orElseGet(() -> roleRepository.save(new Role(AppRole.ROLE_ADMIN)));

        if (!userRepository.existsByUserName("user1")) {
            User user1 = new User("user1", "user1@example.com",
                    passwordEncoder.encode("password1"));
            user1.setAccountNonLocked(false);
            user1.setAccountNonExpired(true);
            user1.setCredentialsNonExpired(true);
            user1.setEnabled(true);
            user1.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            user1.setAccountExpiryDate(LocalDate.now().plusYears(1));
            user1.setTwoFactorEnabled(false);
            user1.setSignUpMethod("email");
            user1.setRole(userRole);
            userRepository.save(user1);
        }

        if (!userRepository.existsByUserName("admin")) {
            User admin = new User("admin", "admin@example.com",
                    passwordEncoder.encode("adminPass"));
            admin.setAccountNonLocked(true);
            admin.setAccountNonExpired(true);
            admin.setCredentialsNonExpired(true);
            admin.setEnabled(true);
            admin.setCredentialsExpiryDate(LocalDate.now().plusYears(1));
            admin.setAccountExpiryDate(LocalDate.now().plusYears(1));
            admin.setTwoFactorEnabled(false);
            admin.setSignUpMethod("email");
            admin.setRole(adminRole);
            userRepository.save(admin);
        }
    }
}
