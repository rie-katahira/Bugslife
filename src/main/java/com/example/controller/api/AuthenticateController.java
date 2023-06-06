package com.example.controller.api;

import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.ErrorResponse;
import org.springframework.web.ErrorResponseException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.JWTVerifier;
import com.example.json.api.Authenticate;
import com.example.model.User;
import com.example.service.UserService;

import jakarta.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/authenticate")
public class AuthenticateController {
	@Value("${jwt.secret}")
	private String secretKey;

	@Autowired
	private UserService userService;

	/**
	 * requestBodyからemailでUserを検索 Userが存在しない場合はエラー Userが存在する場合はパスワードを比較
	 * パスワードが一致しない場合はエラー パスワードが一致する場合はJWTを生成して返す
	 */
	@PostMapping
	@ResponseBody
	public Authenticate.Response authenticate(@RequestBody Authenticate.RequestBody requestBody) {
		// requestBodyからemailでUserを検索
		Optional<User> user = userService.findByEmail(requestBody.getEmail());
		// Userが存在しない場合はエラー
		if (!user.isPresent()) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "User not found");
		}
		// Userが存在する場合はパスワードを比較
		PasswordEncoder passwordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
		if (!passwordEncoder.matches(requestBody.getPassword(), user.get().getPassword())) {
			throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "Password is not correct");
		}
		// パスワードが一致する場合はJWTを生成して返す
		return new Authenticate.Response(generateToken(user.get()));
	}

	@GetMapping("/verifyToken")
	public Authenticate.VerifyTokenResponse verifyToken(HttpServletRequest request) {
		// AuthorizationヘッダーからBearerトークンを取得
		String token = request.getHeader("Authorization").replace("Bearer ", "");
		// JWTの検証
		verifyToken(token);
		return new Authenticate.VerifyTokenResponse("OK");
	}

	@ExceptionHandler(Exception.class)
	public ErrorResponse handleException(Exception exception) {
		return new ErrorResponseException(HttpStatus.BAD_REQUEST, exception);
	}

	/**
	 * JWTの生成
	 */
	private String generateToken(User user) {
		Algorithm alg = Algorithm.HMAC256(secretKey);
		String token = JWT.create().withIssuer("HmacJwtProducer").withSubject(user.getName())
				.withExpiresAt(OffsetDateTime.now().plusMinutes(60).toInstant()).withIssuedAt(OffsetDateTime.now().toInstant())
				.withJWTId(UUID.randomUUID().toString()).withClaim("email", user.getEmail())
				.withArrayClaim("groups", new String[] { "member", "admin" }).sign(alg);
		return token;
	}

	/**
	 * JWTの検証
	 */
	private DecodedJWT verifyToken(String token) {
		Algorithm alg = Algorithm.HMAC256(secretKey);
		JWTVerifier verifier = JWT.require(alg).withIssuer("HmacJwtProducer").acceptExpiresAt(5).build();
		try {
			return verifier.verify(token);
		} catch (JWTVerificationException e) {
			System.out.println("JWT verification failed..");
			throw e;
		}
	}
}
