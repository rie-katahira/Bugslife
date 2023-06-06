package com.example.controller.admin;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/admin")
public class AdminController {

	@GetMapping
	public String index(Model model, Authentication authentication) {
		return "admin/index";
	}

	/**
	 * ファイルダウンロード処理
	 *
	 * @param response
	 * @param redirectAttributes
	 * @return
	 */
	@PostMapping("/download")
	public String download(HttpServletResponse response, RedirectAttributes redirectAttributes) {
		try (OutputStream os = response.getOutputStream();) {
			Path filePath = new ClassPathResource("static/image/confidential_file.png").getFile().toPath();
			byte[] fb1 = Files.readAllBytes(filePath);
			String attachment = "attachment; filename=confidential_file.png";

			response.setContentType("application/octet-stream");
			response.setHeader("Content-Disposition", attachment);
			response.setContentLength(fb1.length);
			os.write(fb1);
			os.flush();
		} catch (IOException e) {
			e.printStackTrace();
		}
		return null;
	}
}
