package com.example.rh.services;

import java.util.List;

import com.example.rh.entities.User;
import com.example.rh.payload.request.SignupRequest;
import org.springframework.http.ResponseEntity;

public interface IUserService {
	public ResponseEntity<?> addUser(SignupRequest signupRequest);
	public User updateUser(SignupRequest personnel,Long id);
	public List<User> getUsers();

}
