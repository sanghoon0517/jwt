package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.web.filter.CorsFilter;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.config.jwt.JwtAuthorizationFilter;
import com.cos.jwt.filter.MyFilter3;
import com.cos.jwt.repository.UserRepository;

import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter{
	
	private final CorsFilter corsFilter;
	private final UserRepository userRepository;
	
	@Bean
	public BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class); //스프링 시큐리티 필터 이전에 동작을 함. 스프링 시큐리티 이후에 MyFilter1,2가 처리된다.
		http.csrf().disable();
		//JWT의 기본 설정 시작
		http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS) // SessionCreationPolicy.STATELESS = 세션을 사용하지 않겠다.
		.and()
		.addFilter(corsFilter) //@CrossOrigin 과의 차이점 : CrossOrigin은 인증이 없는 요청만 처리 가능함(인증이 필요한 요청은 전부 거부됨). CrossOrigin정책
							   //인증이 필요할 때는 시큐리티 필터에 addFilter로 등록을 해야 한다. 즉 필터로 등록하면, 인증이 필요없는 요청과 인증이 필요한 요청 모두 처리 가능하다.  
		.formLogin().disable() //JWT서버이기 때문에 form login을 안한다.
		//JWT의 기본 설정 끝
		.httpBasic().disable() //기본인증방식(세션에 ID와 PW를 달고 요청을 하는 방식)을 쓰지 않겠다. -> Basic방식 말고 Bearer방식(토큰으로 요청하는 방식)을 사용하겠다.
		.addFilter(new JwtAuthenticationFilter(authenticationManager())) //AuthenticationManager 파라미터를 넘겨줘야 한다.
		.addFilter(new JwtAuthorizationFilter(authenticationManager(),userRepository)) //AuthenticationManager 파라미터를 넘겨줘야 한다.
		.authorizeRequests()
		.antMatchers("/api/v1/user/**")
		.access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/manager/**")
		.access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
		.antMatchers("/api/v1/admin/**")
		.access("hasRole('ROLE_ADMIN')")
		.anyRequest().permitAll(); //위의 url경로 외에는 권한없이 접속 가능
		
	}
}
