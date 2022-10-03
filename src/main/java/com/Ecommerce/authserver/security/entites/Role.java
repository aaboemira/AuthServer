package com.Ecommerce.authserver.security.entites;

import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import java.util.Set;
@Entity
public class Role implements GrantedAuthority {
    @Id
    @GeneratedValue(strategy= GenerationType.IDENTITY)
    private long id;
    private String name;
    @ManyToMany(mappedBy = "roles")
    private Set<User> users;
    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    @Override
    public String getAuthority() {
        return this.name;
    }
}
