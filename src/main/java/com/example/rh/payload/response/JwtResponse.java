package com.example.rh.payload.response;

import java.util.List;

public class JwtResponse {
	private String token;
	private String refreshToken;
	private String type = "Bearer";
	private Long id;
	private String username;
	private String email;
	private List<String> roles;

	public JwtResponse(String refreshToken, Long id, String username, String email, List<String> roles,String accessToken) {
		this.token = accessToken;
		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
		this.refreshToken = refreshToken;

	}

	public JwtResponse(Long id, String username, String email, List<String> roles, String accessToken, String refreshToken) {
		this.id = id;
		this.username = username;
		this.email = email;
		this.roles = roles;
		this.token = accessToken;
		this.refreshToken = refreshToken;

	}

	public String getAccessToken() {
		return token;
	}

	public void setAccessToken(String accessToken) {
		this.token = accessToken;
	}

	public String getRefreshToken() {
		return refreshToken;
	}

	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}

	public String getTokenType() {
		return type;
	}

	public void setTokenType(String tokenType) {
		this.type = tokenType;
	}

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getEmail() {
		return email;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public List<String> getRoles() {
		return roles;
	}
}