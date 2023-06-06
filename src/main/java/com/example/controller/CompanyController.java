package com.example.controller;

import java.util.List;
import java.util.Optional;

import org.hibernate.service.spi.ServiceException;
import org.springframework.beans.factory.annotation.Autowired;
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
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.example.constants.Message;
import com.example.model.Company;
import com.example.model.TransactionAmount;
import com.example.service.CompanyService;
import com.example.service.TransactionAmountService;

@Controller
@RequestMapping("/companies")
public class CompanyController {

	@Autowired
	private CompanyService companyService;
	@Autowired
	private TransactionAmountService transactionAmountService;

	/**
	 * 取引先情報の一覧表示
	 *
	 * @param model
	 * @return
	 */
	@GetMapping
	public String index(Model model) {
		List<Company> all = companyService.findAll();
		model.addAttribute("listCompany", all);
		return "company/index";
	}

	/**
	 * 取引先情報の詳細画面表示
	 *
	 * @param model
	 * @param id
	 * @return
	 */
	@GetMapping("/{id}")
	public String show(Model model, @PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
		try {
			if (id != null) {
				Optional<Company> company = companyService.findOne(id);
				List<TransactionAmount> listTAmounts = transactionAmountService.findByCompany(company.get());
				model.addAttribute("company", company.get());
				model.addAttribute("listTAmount", listTAmounts);

				// 収支合計を取得
				Integer tAmountsSum = transactionAmountService.getSumTransactionalAmounts(company.get());
				model.addAttribute("tAmountsSum", tAmountsSum);

				// 収支比率を取得
				Integer tAmountsRatio = transactionAmountService.getRatioTransactionalAmounts(company.get());
				model.addAttribute("tAmountsRatio", tAmountsRatio);
			}
			return "company/show";
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/companies";
		}
	}

	/**
	 * 取引先情報の新規作成処理
	 *
	 * @param model
	 * @param entity
	 * @return
	 */
	@GetMapping(value = "/new")
	public String create(Model model, @ModelAttribute Company entity) {
		model.addAttribute("company", entity);
		return "company/form";
	}

	/**
	 * 取引先情報のUPSERT処理
	 *
	 * @param entity
	 * @param result
	 * @param redirectAttributes
	 * @return
	 */
	@PostMapping
	public String create(@ModelAttribute Company entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		Company company = null;
		try {
			company = companyService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_INSERT);
			return "redirect:/companies/" + company.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/companies";
		}
	}

	/**
	 * 取引先情報の編集画面表示
	 *
	 * @param model
	 * @param id
	 * @return
	 */
	@GetMapping("/{id}/edit")
	public String update(Model model, @PathVariable("id") Long id) {
		try {
			if (id != null) {
				Optional<Company> entity = companyService.findOne(id);
				model.addAttribute("company", entity.get());
			}
		} catch (Exception e) {
			throw new ServiceException(e.getMessage());
		}
		return "company/form";
	}

	/**
	 * 取引先情報の更新処理
	 *
	 * @param entity
	 * @param result
	 * @param redirectAttributes
	 * @return
	 */
	@PutMapping
	public String update(@Validated @ModelAttribute Company entity, BindingResult result,
			RedirectAttributes redirectAttributes) {
		Company company = null;
		try {
			company = companyService.save(entity);
			redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_UPDATE);
			return "redirect:/companies/" + company.getId();
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			e.printStackTrace();
			return "redirect:/companies";
		}
	}

	/**
	 * 取引先情報の削除処理
	 *
	 * @param id 取引先ID
	 * @param redirectAttributes リダイレクト先に値を渡す
	 * @return
	 */
	@DeleteMapping("/{id}")
	public String delete(@PathVariable("id") Long id, RedirectAttributes redirectAttributes) {
		try {
			if (id != null) {
				Optional<Company> entity = companyService.findOne(id);
				companyService.delete(entity.get());
				redirectAttributes.addFlashAttribute("success", Message.MSG_SUCESS_DELETE);
			}
		} catch (Exception e) {
			redirectAttributes.addFlashAttribute("error", Message.MSG_ERROR);
			throw new ServiceException(e.getMessage());
		}
		return "redirect:/companies";
	}
}
