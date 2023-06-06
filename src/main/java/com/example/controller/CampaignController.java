package com.example.controller;

import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import org.hibernate.service.spi.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.constants.Message;
import com.example.enums.CampaignStatus;
import com.example.enums.DiscountType;
import com.example.form.CampaignForm;
import com.example.model.Campaign;
import com.example.model.Category;
import com.example.service.CampaignService;
import com.example.service.CategoryService;
import com.example.utils.CheckUtil;

import jakarta.servlet.http.HttpServletResponse;

@Controller
@RequestMapping("/campaigns")
public class CampaignController {

	@Autowired
	private CampaignService campaignService;

	@Autowired
	private CategoryService categoryService;

	/**
	 * 一覧画面表示
	 *
	 * @param model
	 * @param form
	 * @return
	 */
	@GetMapping
	public String index(Model model, @ModelAttribute("form") CampaignForm form) {
		List<Campaign> all = campaignService.findAll();
		model.addAttribute("campaignList", all);
		model.addAttribute("form", form);
		this.setCommonData(model);
		return "campaign/index";
	}

	/**
	 * 詳細画面表示
	 *
	 * @param model
	 * @param id
	 * @return
	 */
	@GetMapping("/{id}")
	public String show(Model model, @PathVariable("id") Long id) {
		if (id != null) {
			Optional<Category> campaign = categoryService.findOne(id);
			model.addAttribute("campaign", campaign.get());
			this.setCommonData(model);
		}
		return "campaign/show";
	}

	@GetMapping(value = "/new")
	public String create(Model model, @ModelAttribute Campaign campaign) {
		model.addAttribute("campaign", campaign);
		this.setCommonData(model);
		return "campaign/form";
	}

	@PostMapping
	public String create(Model model, @Validated @ModelAttribute Campaign campaign, BindingResult result,
			RedirectAttributes redirectAttributes) {
		if (result.hasErrors()) {
			model.addAttribute("campaign", campaign);
			this.setCommonData(model);
			return "campaign/form";
		}
		Campaign target = null;
		try {
			// descriptionは2000文字まで
			if (!CheckUtil.checkDescriptionLength(campaign.getDescription())) {
				// NG
				redirectAttributes.addFlashAttribute("error", Message.MSG_VALIDATE_ERROR);
				return "redirect:/campaigns";
			}

			target = campaignService.save(campaign);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_INSERT);
			return "redirect:/campaigns/" + target.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/campaigns";
		}
	}

	@GetMapping("/{id}/edit")
	public String update(Model model, @PathVariable("id") Long id) {
		try {
			if (id != null) {
				Optional<Campaign> campaign = campaignService.findOne(id);
				model.addAttribute("campaign", campaign.get());
				this.setCommonData(model);
			}
		} catch (Exception e) {
			throw new ServiceException(e.getMessage());
		}
		return "campaign/form";
	}

	@PutMapping
	public String update(Model model, @Validated @ModelAttribute Campaign campaign, BindingResult result,
			RedirectAttributes redirectAttributes) {
		if (result.hasErrors()) {
			this.setCommonData(model);
			return "campaign/form";
		}
		Campaign target = null;
		try {
			// descriptionは2000文字まで
			if (!CheckUtil.checkDescriptionLength(campaign.getDescription())) {
				// NG
				redirectAttributes.addFlashAttribute("error", Message.MSG_VALIDATE_ERROR);
				return "redirect:/campaigns";
			}

			target = campaignService.save(campaign);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_UPDATE);
			return "redirect:/campaigns/" + target.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/campaigns";
		}
	}

	@DeleteMapping("/{id}")
	public String delete(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
		try {
			if (id != null) {
				Optional<Campaign> campaign = campaignService.findOne(id);
				campaignService.delete(campaign.get());
				redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_DELETE);
			}
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			throw new ServiceException(e.getMessage());
		}
		return "redirect:/campaigns";
	}

	/**
	 * CSVインポート処理
	 *
	 * @param uploadFile
	 * @param redirectAttributes
	 * @return
	 */
	@PostMapping("/upload_file")
	public String uploadFile(@RequestParam("file") MultipartFile uploadFile, RedirectAttributes redirectAttributes) {

		if (uploadFile.isEmpty()) {
			// ファイルが存在しない場合
			redirectAttributes.addFlashAttribute("error", "ファイルを選択してください。");
			return "redirect:/campaigns";
		}
		if (!"text/csv".equals(uploadFile.getContentType())) {
			// CSVファイル以外の場合
			redirectAttributes.addFlashAttribute("error", "CSVファイルを選択してください。");
			return "redirect:/campaigns";
		}
		try {
			campaignService.importCSV(uploadFile);
		} catch (Throwable e) {
			redirectAttributes.addFlashAttribute("error", e.getMessage());
			e.printStackTrace();
			return "redirect:/campaigns";
		}

		return "redirect:/campaigns";
	}

	/**
	 * CSVテンプレートダウンロード処理
	 *
	 * @param response
	 * @param redirectAttributes
	 * @return
	 */
	@PostMapping("/download")
	public String download(HttpServletResponse response, RedirectAttributes redirectAttributes) {

		try (OutputStream os = response.getOutputStream();) {
			Path filePath = new ClassPathResource("static/templates/campaign.csv").getFile().toPath();
			byte[] fb1 = Files.readAllBytes(filePath);
			String attachment = "attachment; filename=campaign_" + new Date().getTime() + ".csv";

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

	/**
	 * 一括ステータス更新処理
	 *
	 * @param form
	 * @param result
	 * @param redirectAttributes
	 * @return
	 */
	@PostMapping("/bulkStatusUpdate")
	public String bulkStatusUpdate(@Validated @ModelAttribute("form") CampaignForm form, BindingResult result,
			RedirectAttributes redirectAttributes) {
		if (result.hasErrors()) {
			redirectAttributes.addFlashAttribute("error", this.makeErrorMessage(result));
			return "redirect:/campaigns";
		}
		try {
			campaignService.bulkStatusUpdate(form.getCheckedIdList(), form.getNextStatus());
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_UPDATE);
			return "redirect:/campaigns";
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", e.getMessage());
			e.printStackTrace();
			return "redirect:/campaigns";
		}
	}

	/**
	 * 共通データを設定する
	 *
	 * @param model
	 */
	private void setCommonData(Model model) {
		model.addAttribute("statusList", CampaignStatus.values());
		model.addAttribute("typeList", DiscountType.values());
	}

	/**
	 * エラーメッセージを作成する
	 *
	 * @param result
	 * @return
	 */
	private String makeErrorMessage(BindingResult result) {
		return String.join("<br/>", result.getAllErrors().stream().map(c -> c.getDefaultMessage())
				.collect(Collectors.toList()));
	}
}
