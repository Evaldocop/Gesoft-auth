package com.gesoft.gesoftauth.core;

import java.util.Collection;
import java.util.stream.Collector;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gesoft.gesoftauth.domain.Usuario;
import com.gesoft.gesoftauth.domain.UsuarioRepository;

@Service
public class JpaUserDetailService implements UserDetailsService {

	@Autowired
	private UsuarioRepository usuarioRepositiry;

	//1
	@Transactional(readOnly = true)
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException { // TODO Auto-generated
																								// method stub

		Usuario usuario = usuarioRepositiry.findByEmail(username)
				.orElseThrow(() -> new UsernameNotFoundException("Usuario não encontrado"));

		return new AuthUser(usuario,getAuthorities(usuario));
	}

	
	private Collection<GrantedAuthority> getAuthorities(Usuario usuario){
		
		return usuario.getGrupos().stream()
		                    .flatMap(grupo-> grupo.getPermissoes().stream())
		                    .map(permissao-> new SimpleGrantedAuthority(permissao.getNome().toUpperCase()))
		                    .collect(Collectors.toSet());
		
	}
}
