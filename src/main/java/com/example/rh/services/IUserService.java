package com.example.rh.services;

import java.util.List;

import com.example.rh.entities.User;

public interface IUserService {
	//public boolean effectuerPostulation(Long id );
	public List<User> getUsers();
	//public List<OffreEmploi> getPostulation(Long id) ;
	public void supprimerUser(Long id);
}
