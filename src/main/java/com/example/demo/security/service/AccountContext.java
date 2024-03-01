package com.example.demo.security.service;

import com.example.demo.Entity.Account.Account;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import java.util.Collection;

public class AccountContext extends User {

    private final Account account;

    public AccountContext(Account account, Collection<? extends GrantedAuthority> authorities) {
        super(account.getUserId(), account.getUserPw(), authorities);
        this.account = account;
    }

    public Account getAccount() {
        return account;
    }
}
