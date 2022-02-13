package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
	
	@Bean
	public CorsFilter corsFilter() {
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		CorsConfiguration config = new CorsConfiguration();
		config.setAllowCredentials(true); //내 서버가 응답할 때, json을 자바스크립트에서 처리할 수 있게 할지 설정하는 것 //false가 걸려있으면 자바스크립트로 요청시 응답이 오지 않음
		config.addAllowedOrigin("*"); //모든IP에 대해 응답을 허용을 해줌
		config.addAllowedHeader("*"); //모든 header에 등답을 허용하겠다.
		config.addAllowedMethod("*"); //모든 HTTP메소드(post,get,put,patch,delete 등등)를 허용하겠다.
		source.registerCorsConfiguration("/api/**", config);
		return new CorsFilter(source);
	}
}
