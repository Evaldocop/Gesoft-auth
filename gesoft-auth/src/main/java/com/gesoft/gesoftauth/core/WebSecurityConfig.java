package com.gesoft.gesoftauth.core;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;



@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
	
	
	
	// configuração de usuários em memoria
	//buider
	
	/*
	 * protected void configure(AuthenticationManagerBuilder auth) throws Exception
	 * {
	 * 
	 * auth.inMemoryAuthentication() .withUser("evaldo")
	 * .password(passwordEncoder().encode("20131show")) .roles("ADMIN") .and()
	 * .withUser("gustavo") .password(passwordEncoder().encode("20131show"))
	 * .roles("ADMIN"); }
	 */
	
	
	
	@Bean
	public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
	
	}
	
	@Bean
	protected AuthenticationManager   authenticationManager() throws Exception {
		return super.authenticationManager();
		
	}
	

}
