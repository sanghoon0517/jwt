package com.cos.jwt.config.jwt;

import java.io.IOException;
import java.util.Date;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;

import lombok.RequiredArgsConstructor;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// /login POST로 요청해서 username, password를 전송하면, 
// UsernamePasswordAuthenticationFilter가 동작한다.
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{
	
	private final AuthenticationManager authenticationManager; //RequiredArgsConstructor에 의해 해당 필드를 가져야하는 생성자가 자동으로 생김
	
	// /login 요청을 하면 로그인 시도를 위해 실행되는 함수
	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {
		System.out.println("JwtAuthenticationFilter : 로그인 시도중");
		
		//1. username, password를 받아서
		try {
//			BufferedReader br = request.getReader();
//			String input = null;
//			while((input=br.readLine()) != null) {
//				System.out.println(input);
//			}
			ObjectMapper om = new ObjectMapper(); //json데이터를 파싱해줌
			User user = om.readValue(request.getInputStream(), User.class);
			System.out.println(user);
			
			//토큰만들기
			UsernamePasswordAuthenticationToken authenticationToken = 
					new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());
			
			//PrincipalDetailsService의 loadUserByUsername() 메서드가 실행된다.
			//정상적으로 로그인이 되었을 경우, authentication객체가 리턴된다. 내 로그인한 정보가 authentication에 담긴다.
			//DB에 있는 username과 password가 일치한다는 의미고, 즉 '인증'이 된다.
			Authentication authentication = authenticationManager.authenticate(authenticationToken);
			
			//로그인이 정상적으로 이루어졌다는 뜻
			PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal(); 
			System.out.println("로그인완료 username : "+principalDetails.getUser().getUsername());
			System.out.println("로그인완료 password : "+principalDetails.getUser().getPassword());
			
			//return을 하게되면 authentication 객체가 session 영역에 저장된다.
			//session 영역에 저장하는 이유는 권한관리를 스프링시큐리티가 관리를 해주기 때문이다.
			//굳이 JWT를 사용하면서 세션을 만들 이유는 없지만, 단지 권한 처리 때문에 session에 넣어준다.
			return authentication;
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.println("======================================");
		
		//2. 정상인지 로그인 시도를 해본다. authenticationManager로 로그인 시도를 하게 되면 
		//PrincipalDetailsService가 호출되고, loadUserByUsername()가 실행된다.
		
		//3. PrincipalDetails를 세션에 담고 (세션에 담는 이유는 권한관리를 하기 위해서..ex) ADMIN, MANAGER, USER의 권한관리)
		
		//4. JWT토큰을 만들어서 응답해주면 된다.
		return null;
	}
	
	//attemptAuthentication실행 후 인증이 정상적으로 되었으면, successfullAuthentication() 메서드가 실행된다.
	//그렇다면, 여기서 JWT토큰을 만들어서 request요청한 사용자에게 JWT토큰을 response해주면 된다.
	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {
		System.out.println("successfulAuthentication 실행됨 : 인증완료");
		PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();
		
		//RSA가 아니고 Hash암호화방식
		//pom.xml에 java-jwt 라이브러리를 다운받아놔서 JWT클래스 사용가능
		String jwt = JWT.create()
				.withSubject("jwt-test-token")
				.withExpiresAt(new Date(System.currentTimeMillis()+JwtProperties.EXPIRATION_TIME)) //현재시간+ (6000*10=10분) //토큰만료시간 10분
				.withClaim("id", principalDetails.getUser().getId())
				.withClaim("username", principalDetails.getUser().getUsername())
				.sign(Algorithm.HMAC512(JwtProperties.SECRET));
		
		response.addHeader(JwtProperties.HEADER_STRING, JwtProperties.TOKEN_PREFIX+jwt);
	}
}
