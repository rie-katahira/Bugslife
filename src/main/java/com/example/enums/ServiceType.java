package com.example.enums;

import com.example.constants.Service;
import com.example.model.App;
import com.example.model.Campaign;
import com.example.model.Category;
import com.example.model.Company;
import com.example.model.Order;
import com.example.model.Product;
import com.example.model.Shop;
import com.example.model.TransactionAmount;
import com.example.model.User;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum ServiceType {
  APP(Service.APP, "アプリケーション", App.class),
  CAMPAIGN(Service.CAMPAIGN, "キャンペーン", Campaign.class),
  CATEGORY(Service.CATEGORY, "カテゴリー", Category.class),
  COMPANY(Service.COMPANY, "取引先", Company.class),
  ORDER(Service.ORDER, "受注", Order.class),
  SHOP(Service.SHOP, "店舗", Shop.class),
  PRODUCT(Service.PRODUCT, "商品", Product.class),
  TRANSACTION_AMOUNT(Service.TRANSACTION_AMOUNT, "取引金額", TransactionAmount.class),
  USER(Service.USER, "ユーザ", User.class);

  private String code;
  private String value;
  private Class<?> instance;

  /**
   * クラスを返す.
   *
   * @param code コード
   * @return 値を返す
   */
  public static Class<?> classOf(String code) {
    for (ServiceType type : values()) {
      if (type.code.equals(code)) {
        return type.instance;
      }
    }
    return null; // 特定できない場合
  }
}
