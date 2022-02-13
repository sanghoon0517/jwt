package com.cos.jwt.filter;

import java.io.IOException;
import java.io.PrintWriter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyFilter3 implements Filter{
	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletRequest req = (HttpServletRequest) request;
		HttpServletResponse res = (HttpServletResponse) response;
		
		//토큰 : cos 라는 임의의 값 <- 이걸 만들어줘야함//id,pw가 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답으로 내보낸다.
		//요청할 때마다 header에 Authorization에 value값으로 토큰을 가지고 올 것임
		//그 때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 된다.(RSA or HS256 방식)
		if(req.getMethod().equals("POST")) {
			System.out.println("POST 요청됨");
			String headerAuth = req.getHeader("Authorization");
			System.out.println("Authorization : "+headerAuth);
			
			if(headerAuth.equals("cos")) { //Authorization 값
				chain.doFilter(req, res); //이 함수 실행 이후 그다음 프로세스 진행
			} else {
				PrintWriter out = res.getWriter();
				out.print("인증안됨");
			}
		}
		System.out.println("필터3");
	}
}
