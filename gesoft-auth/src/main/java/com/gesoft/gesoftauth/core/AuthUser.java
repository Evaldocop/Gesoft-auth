
package com.gesoft.gesoftauth.core;

import java.util.Collection;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import com.gesoft.gesoftauth.domain.Usuario;
import com.gesoft.gesoftauth.domain.UsuarioRepository;

import lombok.Getter;

@Getter
public class AuthUser extends User {

	private static final long serialVersionUID = 1L;
    @Autowired
    private UsuarioRepository usuarioRepository;
	
	private Long id;
	private String fullName;

	public AuthUser(Usuario usuario, Collection<? extends GrantedAuthority> autorities) {
		super(usuario.getEmail(), usuario.getSenha(),autorities);
		this.fullName = usuario.getNome();
		this.id= usuario.getId();
	}

}
