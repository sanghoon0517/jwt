package com.cos.jwt.config.jwt;

public interface JwtProperties {
	String SECRET = "cos"; //우리 서버가 갖고 있는 secret값
	int EXPIRATION_TIME = 6000*10; //
	String TOKEN_PREFIX = "Bearer ";
	String HEADER_STRING = "Authorization";
}
