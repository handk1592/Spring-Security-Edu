package io.security.basicsecurity.domain;

import lombok.Data;

@Data
public class AccountDto {

	private Long Id;
	private String username;
	private String password;
	private String email;
	private String age;
	private String role;
	
}
