package com.ojasare.secure_notes.repository;

import com.ojasare.secure_notes.models.AppRole;
import com.ojasare.secure_notes.models.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long> {
    Optional<Role> findByRoleName(AppRole appRole);
}
