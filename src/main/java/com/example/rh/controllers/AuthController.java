package com.example.rh.controllers;

import java.io.IOException;
import java.util.*;
import java.util.stream.Collectors;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.example.rh.services.IUserService;

import lombok.Data;

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

@CrossOrigin(origins = "http://localhost:4200", maxAge = 3600)
@RestController
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

	@CrossOrigin(origins = "http://localhost:4200")
	@PostMapping("/elogin")
	public ResponseEntity<?> authToken(@Valid @RequestBody LoginRequest loginRequest , HttpServletRequest request) throws IOException {
		Authentication authentication = authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(loginRequest.getUsername(), loginRequest.getPassword()));
		SecurityContextHolder.getContext().setAuthentication(authentication);
		org.springframework.security.core.userdetails.User authenticatedUser= (org.springframework.security.core.userdetails.User) authentication.getPrincipal();
		Algorithm algorithm=Algorithm.HMAC256("myHMACPrivateKey");
		String jwtAccessToken= JWT
				.create()
				.withSubject(authenticatedUser.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+30*60*1000))
				.withIssuer(request.getRequestURL().toString())
				.withClaim("roles",authenticatedUser.getAuthorities().stream().map((a)->a.getAuthority()).collect(Collectors.toList()))
				.sign(algorithm);
		String jwtRefreshToken= JWT
				.create()
				.withSubject(authenticatedUser.getUsername())
				.withExpiresAt(new Date(System.currentTimeMillis()+60*24*3600*1000))
				.withIssuer(request.getRequestURL().toString())
				.sign(algorithm);

		User u = userRepository.findByUsername(authenticatedUser.getUsername()).get();
		List<String> roles = new ArrayList<>();
				u.getRoles().forEach(role -> {
				roles.add(role.getName().name());
		});

		return ResponseEntity.ok(new JwtResponse(u.getId(),
				u.getUsername(),
				u.getEmail(),
				roles,
				jwtAccessToken,
				jwtRefreshToken
				));

	}


	@PostMapping("/addUser")
	@PreAuthorize("hasRole('ADMIN')")
	public void registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
		System.out.println(signUpRequest.getEmail()+signUpRequest.getRole());
		 userService.addUser(signUpRequest);
	}

	@PostMapping("/addRole")
	@PreAuthorize("hasRole('ADMIN')")
	public Role addRole(@RequestBody role r) {
		
		ERole e= ERole.ROLE_USER;
		if(r.name.compareTo("admin")==0)
		{
			e=ERole.ROLE_ADMIN;
			
		}
		
		Role rr =new Role();
		rr.setId(null);
		rr.setName(e);
		
		
	return roleRepository.save(rr);

	}
	@PutMapping("/user/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public User updateUser(@RequestBody SignupRequest personnel, @PathVariable Long id) {
		return userService.updateUser(personnel, id);

	}
	@GetMapping("/user/{id}")
	@PreAuthorize("hasRole('ADMIN')")
	public User getOneUser(@PathVariable Long id) {
		return userRepository.findById(id).get();

	}

	@PostMapping("allUsersById")
	public List<User> allUsersByListOfId(@RequestBody List<Long> ids) {
		List<User> l = new ArrayList<>();
		ids.forEach(id -> {
			l.add(userRepository.findById(id).get());
		});
		return l;
	}

	@GetMapping("allusers")
	public List<User> allUsers(){
		return userRepository.findAll();
	}

	@GetMapping("/userauthenticated/{u}")
	public User getAuthenticatedUserFromUsername(@PathVariable String u){
		return userRepository.findByUsername(u).get();
	}

}


@Data
class role
{
	
	
	String name;
	
}