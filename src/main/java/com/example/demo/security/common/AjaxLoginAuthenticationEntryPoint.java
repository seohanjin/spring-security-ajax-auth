package com.example.demo.security.common;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class AjaxLoginAuthenticationEntryPoint implements AuthenticationEntryPoint {

    /*
        익명 사용자가 해당 자원에 인정이 필요한 자원에 접근했을 경우 예외 필터가 해당 메서드 호출 후 클라이언트에 전달
     */
    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "UnAuthorized");
    }
}
