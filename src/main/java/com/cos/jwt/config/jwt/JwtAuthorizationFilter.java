package com.cos.jwt.config.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;

/**
 * @author 전상훈
 * 
 * 시큐리티가 filter를 가지고 있는데 그 필터 중에 BasicAuthenticationFilter라는 게 있음
 * 권한이나 인증이 필요한 특정 주소를 요청했을 때, 위 필터를 무조건 타게 되어있다.
 * 만약에 권한이나 인증이 필요한 주소가 아니라면, 해당 필터를 타지 않는다.
 *
 */
public class JwtAuthorizationFilter extends BasicAuthenticationFilter{
	
	private UserRepository userRepository;

	public JwtAuthorizationFilter(AuthenticationManager authenticationManager, UserRepository userRepository) {
		super(authenticationManager);
		this.userRepository = userRepository;
	}
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws IOException, ServletException {
//		super.doFilterInternal(request, response, chain); //이걸 지우지 않으면 응답을 2번하면서 에러가 난다.
		System.out.println("인증이나 권한이 필요한 주소 요청이 됨");
		
		String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
		System.out.println("jwtHeader : "+jwtHeader);
		
		//header가 있는지 확인
		if(jwtHeader == null || !jwtHeader.startsWith("Bearer")) { //잘못된 Authorization이 온다면
			chain.doFilter(request, response);
			return;
		}
		
		//JWT토큰을 검증해서 정상적인 사용자인지 확인
		String jwt = request.getHeader("Authorization").replace(JwtProperties.TOKEN_PREFIX, ""); //순수 JWT만 받기 위함
		
		String username = JWT.require(Algorithm.HMAC512("cos")).build().verify(jwt).getClaim("username").asString();
		
		//username이 null이 아닌경우는 서명이 제대로 됐다는 의미
		if(username != null) {
			User userEntity = userRepository.findByUsername(username);
			
			PrincipalDetails principalDetails = new PrincipalDetails(userEntity);
			
			//JWT 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
			Authentication authentication = new UsernamePasswordAuthenticationToken(principalDetails, null,principalDetails.getAuthorities());
			
			//강제로 시큐리티의 세션에 접근하여 AUthentication 객체를 저장 (강제 로그인)
			SecurityContextHolder.getContext()/*시큐리티 세션 공간 확보*/.setAuthentication(authentication);
			
			chain.doFilter(request, response);
		}
	}
}
