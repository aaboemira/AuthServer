package com.Ecommerce.authserver.security.Repos;

import com.Ecommerce.authserver.security.entites.Role;
import org.springframework.data.jpa.repository.JpaRepository;



public interface RoleRepo extends JpaRepository<Role, Long> {

}
