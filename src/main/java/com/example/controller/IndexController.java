package com.example.controller;

import org.springframework.web.bind.annotation.GetMapping;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import com.example.security.UrlRecordingFilter.UrlRecording;

import jakarta.servlet.http.HttpSession;

@Controller
@RequestMapping("/")
public class IndexController {
	@Autowired
	RequestMappingHandlerMapping requestMappingHandlerMapping;

	@GetMapping
	public String index(Model model, HttpSession session) {
		List<String> list = this.requestMappingHandlerMapping.getHandlerMethods()
				.entrySet().stream()
				.filter(endpoint -> endpoint.getValue().toString().contains("index"))
				.map(e -> e.getKey().toString().replace("{GET [", "").replace("]}", ""))
				// 第一階層のみとして/が複数ある場合は除外する
				.filter(endpoint -> endpoint.indexOf("/", 1) == -1)
				.sorted().collect(Collectors.toList());
		model.addAttribute("endpoints", list);

		var urlRecordingAttribute = session.getAttribute("urlRecording");
		if (urlRecordingAttribute instanceof UrlRecording) {
			UrlRecording urlRecording = (UrlRecording)urlRecordingAttribute;
			// 逆順に並び替えてセットする
			var urls = urlRecording.getUrls();
			Collections.reverse(urls);
			model.addAttribute("urlRecording", urls);
		}
		return "index";
	}

}
