package com.example.json.api;

public class Authenticate {
	public static class RequestBody {
		private String email;
		private String password;

		public String getEmail() {
			return email;
		}

		public void setEmail(String email) {
			this.email = email;
		}

		public void setPassword(String password) {
			this.password = password;
		}

		public String getPassword() {
			return password;
		}
	}

	public static class Response {
		private String token;

		public Response(String token) {
			this.token = token;
		}

		public String getToken() {
			return token;
		}
	}

	public static class VerifyTokenResponse {
		private String result;

		public VerifyTokenResponse(String result) {
			this.result = result;
		}

		public String getResult() {
			return result;
		}
	}
}
