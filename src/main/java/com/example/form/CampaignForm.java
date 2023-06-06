package com.example.form;

import java.util.ArrayList;
import java.util.List;

import com.example.enums.CampaignStatus;

import jakarta.validation.constraints.NotEmpty;
import lombok.Data;

@Data
public class CampaignForm {
	@NotEmpty(message = "必ず一つは選択してください。")
	private List<Long> checkedIdList = new ArrayList<Long>();
	private CampaignStatus nextStatus = CampaignStatus.valueOf(0);

}
