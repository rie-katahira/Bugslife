package com.example.constants;

import java.util.ArrayList;
import java.util.List;

public final class TaxType {
	/**
	 * Rate
	 */
	public static final Integer RATE_0 = 0;
	public static final Integer RATE_8 = 8;
	public static final Integer RATE_10 = 10;

	/**
	 * Rounding
	 */
	public static final String FLOOR = "floor";
	public static final String ROUND = "round";
	public static final String CEIL = "ceil";

	private TaxType() {}

	public final static class Tax {
		public Integer id;
		public Integer rate;
		public Boolean taxIncluded;
		public String rounding;

		public Tax(Integer id, Integer rate, Boolean taxIncluded, String rounding) {
			this.id = id;
			this.rate = rate;
			this.taxIncluded = taxIncluded;
			this.rounding = rounding;
		}
	}

	public static List<Tax> get() {
		List<Tax> taxes = new ArrayList<>();
		int[] rates = { RATE_0, RATE_8, RATE_10 };
		boolean[] taxIncludeds = { false, true };
		String[] roundings = { FLOOR, ROUND, CEIL };
		for (int rate : rates) {
			for (boolean taxIncluded : taxIncludeds) {
				for (String rounding : roundings) {
					taxes.add(new Tax(taxes.size() + 1, rate, taxIncluded, rounding));
				}
			}
		}
		return taxes;
	}

	public static Tax get(Integer id) {
		List<Tax> taxes = get();
		for (Tax tax : taxes) {
			if (tax.id.equals(id)) {
				return tax;
			}
		}
		return null;
	}

	public static Tax get(Integer rate, Boolean taxIncluded, String rounding) {
		List<Tax> taxes = get();
		for (Tax tax : taxes) {
			if (tax.rate.equals(rate) && tax.taxIncluded.equals(taxIncluded) && tax.rounding.equals(rounding)) {
				return tax;
			}
		}
		return null;
	}
}
