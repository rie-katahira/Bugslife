package com.example.security;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.example.repository.UserRepository;

public class CustomInMemoryUserDetailsManager extends InMemoryUserDetailsManager {
	@Autowired
	UserRepository repository;
	private final PasswordEncoder passwordEncoder;

	public CustomInMemoryUserDetailsManager(UserDetails... users) {
		super(users);
		this.passwordEncoder = passwordEncoder();
	}

	/**
	 * usersテーブルから先に検索を行い、あれば {@see InMemoryUserDetailsManager} に追加する。
	 */
	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		var user = repository.findByEmail(username);
		if (user.isPresent()) {
			String password = user.get().getPassword();
			Pattern pattern = Pattern.compile("^\\{.+\\}.+");
			Matcher matcher = pattern.matcher(password);
			if (!matcher.find()) {
				password = "{noop}" + passwordEncoder.encode(password);
			}
			UserDetails userDetails = User.builder()
					.username(user.get().getEmail())
					.password(password)
					.roles(user.get().getRoleEnum().getRole())
					.build();
			// 既に登録されているかもしれないので、一旦削除してから追加する。
			deleteUser(userDetails.getUsername());
			createUser(userDetails);
		}
		return super.loadUserByUsername(username);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

}