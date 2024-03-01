package com.example.demo.Entity.Account;

import lombok.AccessLevel;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
@Getter
@NoArgsConstructor(access = AccessLevel.PROTECTED)
public class Account {

    @Id
    private String userId;
    private String userPw;
    private String role;

    @Builder
    public Account(String userId, String userPw) {
        this.userId = userId;
        this.userPw = userPw;
    }


}
