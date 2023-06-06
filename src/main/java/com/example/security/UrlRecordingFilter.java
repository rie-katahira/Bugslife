package com.example.security;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.stereotype.Component;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

@Component
public class UrlRecordingFilter implements Filter {

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		if (request instanceof HttpServletRequest) {
			HttpServletRequest httpRequest = (HttpServletRequest)request;

			// Ignore the static resource URLs
			if (!isIgnorePattern(httpRequest)) {
				HttpSession session = httpRequest.getSession();
				String requestURL = httpRequest.getRequestURI().toString();
				UrlRecording urlRecording = (UrlRecording)session.getAttribute("urlRecording");
				if (urlRecording == null) {
					urlRecording = new UrlRecording();
				}
				urlRecording.add(requestURL);
				session.setAttribute("urlRecording", urlRecording);
			} else if (isDeleteMethod(httpRequest)) {
				HttpSession session = httpRequest.getSession();
				String requestURL = httpRequest.getRequestURI().toString();
				UrlRecording urlRecording = (UrlRecording)session.getAttribute("urlRecording");
				if (urlRecording == null) {
					urlRecording = new UrlRecording();
				}
				urlRecording.delete(requestURL);
				session.setAttribute("urlRecording", urlRecording);

			}

		}

		chain.doFilter(request, response);
	}

	private static boolean isIgnorePattern(HttpServletRequest request) {
		String requestURL = request.getRequestURI().toString();
		String requestMethod = request.getMethod();
		// Ignore the static resource URLs
		return requestURL.endsWith("favicon.ico")
				|| requestURL.endsWith(".css")
				|| requestURL.endsWith(".js")
				|| requestURL.equals("/")
				// Ignore the not GET requests
				|| !requestMethod.equals("GET")
				// Ignore the login/logout URLs
				|| requestURL.endsWith("/auth/login");
	}

	/**
	 * DELETEメソッドの判定
	 */
	private static boolean isDeleteMethod(HttpServletRequest request) {
		return request.getMethod().equals("DELETE");
	}

	public static class UrlRecording {
		/**
		 * URLのリスト
		 */
		private List<String> urls = new ArrayList<>();

		public List<String> getUrls() {
			// コピーを作成して渡す
			return new ArrayList<>(urls);
		}

		public void add(String url) {
			/**
			 * 最後尾と同じURLは追加しない
			 */
			if (urls.size() > 0 && urls.get(urls.size() - 1).equals(url)) {
				return;
			}
			urls.add(url);
			/**
			 * 追加後に10件以上であれば先頭を削除
			 */
			if (urls.size() > 10) {
				urls.remove(0);
			}
		}

		/**
		 * 指定したURLと先頭から一致するURLを削除する
		 *
		 * @param url
		 */
		public void delete(String url) {
			urls.removeIf(s -> s.startsWith(url));
		}
	}
}
