package com.example.rh.controllers;

import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import javax.validation.Valid;

import com.example.rh.services.IUserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import com.example.rh.entities.ERole;
import com.example.rh.entities.Role;
import com.example.rh.entities.User;
import com.example.rh.payload.request.LoginRequest;
import com.example.rh.payload.request.SignupRequest;
import com.example.rh.payload.response.JwtResponse;
import com.example.rh.payload.response.MessageResponse;
import com.example.rh.repository.RoleRepository;
import com.example.rh.repository.UserRepository;
import com.example.rh.security.services.UserDetailsImpl;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/auth/admin")
public class AuthController {
	@Autowired
	AuthenticationManager authenticationManager;

	@Autowired
	UserRepository userRepository;

	@Autowired
	RoleRepository roleRepository;

	@Autowired
	PasswordEncoder encoder;

	@Autowired
	IUserService userService;

	@PostMapping("/addUser")
	@PreAuthorize("hasRole('ADMIN')")
	public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		return userService.addUser(signUpRequest);
	}

	@PutMapping("/user/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public User updateUser(@RequestBody SignupRequest personnel, @PathVariable Long id) {
		return userService.updateUser(personnel, id);

	}
}
