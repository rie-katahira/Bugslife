package com.example.controller.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/auth")
public class LoginController {
	@GetMapping(path = "login")
	String login() {
		return "auth/login";
	}
}
