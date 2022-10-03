package com.Ecommerce.authserver.security.Repos;


import com.Ecommerce.authserver.security.entites.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepo extends JpaRepository<User, Long> {
    User findByEmail(String email);
}
