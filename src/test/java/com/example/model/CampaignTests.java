package com.example.model;

import java.util.stream.Stream;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;

import com.example.enums.DiscountType;
import com.example.repository.CampaignRepository;

@SpringBootTest
@AutoConfigureMockMvc
public class CampaignTests {
	@Autowired
	private CampaignRepository campaignRepository;

	/**
	 * Campaignのstatusのテスト
	 */
	@ParameterizedTest
	@MethodSource("methodParameter")
	public void statusTest(String fromDate, String toDate, int discountType, String expected) {
		Campaign campaign = new Campaign();
		campaign.setCode("test");
		campaign.setName("test");
		campaign.setDescription("test");
		// Arrange
		campaign.setFromDate(fromDate);
		campaign.setToDate(toDate);
		campaign.setDiscountType(DiscountType.valueOf(discountType));
		// Act
		campaignRepository.save(campaign);
		// Assert
		Assertions.assertEquals(expected, campaign.getStatus());
	}

	static Stream<Arguments> methodParameter() {
		return Stream.of(
				Arguments.of("2021-01-01", "2021-01-02", 1, "pass", "正常A"),
				Arguments.of("2021-01-01", "2021-01-02", 2, "pass", "正常B"),
				Arguments.of("2021-01-01", "2021-01-02", 3, "pass", "正常C")
		// TODO: fix tests
		// Arguments.of("2021-01-01", "2021-01-02", "D", "pass", "discountTypeが異常")
		// Arguments.of("", "2021-01-02", "A", "fail", "fromDateが空"),
		// Arguments.of("2021-01-01", "", "A", "fail", "toDateが空"),
		// Arguments.of("2021-01-03", "2021-01-02", "A", "fail", "fromDateがtoDateより大きい")
		);
	}
}
