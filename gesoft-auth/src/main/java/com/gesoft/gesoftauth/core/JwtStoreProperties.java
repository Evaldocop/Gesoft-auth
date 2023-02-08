package com.gesoft.gesoftauth.core;

import javax.validation.constraints.NotNull;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;
import org.springframework.validation.annotation.Validated;

@Validated
@Component
@ConfigurationProperties("gesoftfood.jwt.store")
public class JwtStoreProperties {

	@NotNull
	private String path;
	
	@NotNull
	private String password;
	
	@NotNull
	private String keypairAlias;

	public String getPath() {
		return path;
	}

	public void setPath(String path) {
		this.path = path;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}

	public String getKeypairAlias() {
		return keypairAlias;
	}

	public void setKeypairAlias(String keypairAlias) {
		this.keypairAlias = keypairAlias;
	}
	
	
	
	
}
