package com.example.demo.security.provider;

import com.example.demo.security.service.AccountContext;
import com.example.demo.security.token.AjaxAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
@RequiredArgsConstructor
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    private final UserDetailsService userDetailsService;
    private final PasswordEncoder passwordEncoder;

    /**
     * (인증에 관련된) 검증을 위한 구현 메서드
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        // 파라미터 authentication : AuthenticationManager 클래스로부터 전달받은 인증 객체 (아이디, 패스워드 정보가 담겨있음)
        String userId = authentication.getName();
        String password = (String) authentication.getCredentials();

        AccountContext accountContext = (AccountContext)userDetailsService.loadUserByUsername(userId);

        if(!passwordEncoder.matches(password, accountContext.getAccount().getUserPw())) {
            throw new BadCredentialsException("인증에 실패하였습니다.");
        }

        return new AjaxAuthenticationToken(accountContext.getAccount(), null, accountContext.getAuthorities());
    }

    /**
     * 파라미터로 전달되는 authentication 클래스 타입과
     * CustomAuthenticationProvider 가 사용하는 토큰의 타입과 일치할 때
     * 해당 provider 인증 처리를 할 수 있도록 조건을 준다.
     */
    @Override
    public boolean supports(Class<?> authentication) {
        return authentication.equals(AjaxAuthenticationToken.class);
    }
}
