package com.example.demo.security.filter;

import com.example.demo.Entity.Account.AccountDto;
import com.example.demo.security.token.AjaxAuthenticationToken;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.thymeleaf.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * 기존에 존재하는 UsernamePasswordFilter 가 아닌 새로운 필터 생성
 */
public class AjaxLoginProcessingFilter extends AbstractAuthenticationProcessingFilter {

    private ObjectMapper objectMapper = new ObjectMapper();

    /**
     * "/api/login" url 로 요청이 들어왔을 떄만 해당 필터 작동하도록 구성
     */
    public AjaxLoginProcessingFilter() {
        super(new AntPathRequestMatcher("/api/login", "POST"));
    }

    /**
     * 요청한 방식이 Ajax 여부에 따라서 작동하도록 구성
     */
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {

        if(!isAjax(request)) {
            throw  new IllegalStateException("Authentication is not supported");
        }

        AccountDto accountDto = objectMapper.readValue(request.getReader(), AccountDto.class);
        if (StringUtils.isEmpty(accountDto.getUserId()) || StringUtils.isEmpty(accountDto.getUserPw())) {
            throw new IllegalArgumentException("UserId or UserPassword is empty");
        }

        AjaxAuthenticationToken ajaxAuthenticationToken = new AjaxAuthenticationToken(accountDto.getUserId(), accountDto.getUserPw());

        // AuthenticationProcessingFilter -> AuthenticationManager 로 전달
        return getAuthenticationManager().authenticate(ajaxAuthenticationToken);
    }

    /*
        request 객체의 헤더에 X-Request-With 의 값이 XMLHttpRequest 인지 아닌지에 따라서 Ajax 여부 확인 (클라이언트 쪽과 약속된 정보)
     */
    private boolean isAjax(HttpServletRequest request) {

        if ("XMLHttpRequest".equals(request.getHeader("X-Requested-With"))) {
            return true;
        }

        return false;
    }
}
