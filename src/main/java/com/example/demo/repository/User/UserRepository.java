package com.example.demo.repository.User;

import com.example.demo.Entity.Account.Account;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<Account, String> {

    Account findByUserId(String userId);
}
