package com.example.demo.controller.user;

import com.example.demo.Entity.Account.Account;
import com.example.demo.Entity.Account.AccountDto;
import com.example.demo.service.User.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@RequiredArgsConstructor
public class RegisterController {

    private final UserService userService;
    private final PasswordEncoder passwordEncoder;

    @GetMapping("/register")
    public String createUser() {
        return "user/login/register";
    }

    @PostMapping("/register")
    public String createUser(AccountDto accountDto) {

        Account account = Account.builder()
                .userId(accountDto.getUserId())
                .userPw(passwordEncoder.encode(accountDto.getUserPw()))
                .build();

        userService.createUser(account);

        return "redirect:/";
    }
}
