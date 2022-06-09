package com.example.rh;

import io.jsonwebtoken.Jwts;

import java.util.Set;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.rest.core.config.RepositoryRestConfiguration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.rh.payload.request.SignupRequest;
import com.example.rh.services.UserServiceImpl;

@SpringBootApplication
public class AuthenticationApplication {
  
	public static void main(String[] args) {
		SpringApplication.run(AuthenticationApplication.class, args);
	}

	@Bean
	PasswordEncoder passwordEncoder(){
		return new BCryptPasswordEncoder();
	}


	@Bean
	CommandLineRunner start(RepositoryRestConfiguration repositoryRestConfiguration){
		return args -> {
			/*  Set<String> r = null;
			  r.add("ROLE_ADMIN");
SignupRequest s= new SignupRequest();
s.setEmail("loubna@gmail.com");
s.setPassword("123456");
s.setRole(r);
s.setUsername("loubna");

serv.addUser(s);
			*/
		};
	}

}
