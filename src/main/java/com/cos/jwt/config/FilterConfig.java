package com.cos.jwt.config;

import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;

@Configuration
public class FilterConfig {
	
	@Bean
	public FilterRegistrationBean<MyFilter1> filter() {
		FilterRegistrationBean<MyFilter1> bean = new FilterRegistrationBean<>(new MyFilter1());
		bean.addUrlPatterns("/*"); //모든 요청에서 다 처리해라
		bean.setOrder(0); //낮은 번호가 필터 중에서 가장 먼저 실행됨.
		return bean;
	}
	
	@Bean
	public FilterRegistrationBean<MyFilter2> filter2() {
		FilterRegistrationBean<MyFilter2> bean = new FilterRegistrationBean<>(new MyFilter2());
		bean.addUrlPatterns("/*"); //모든 요청에서 다 처리해라
		bean.setOrder(0); //낮은 번호가 필터 중에서 가장 먼저 실행됨.
		return bean;
	}
}
