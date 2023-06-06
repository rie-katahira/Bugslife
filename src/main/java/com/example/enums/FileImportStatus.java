package com.example.enums;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public enum FileImportStatus {
  IMPORTING(0, "取込中"),
  COMPLETE(1, "取込完了"),
  ERROR(2, "取込失敗");

  private Integer code;
  private String value;

  /**
   * 値を返す.
   *
   * @param code コード
   * @return 値を返す
   */
  public static FileImportStatus valueOf(Integer code) {
    for (FileImportStatus value : values()) {
      if (value.code.equals(code)) {
        return value;
      }
    }
    return null; // 特定できない場合
  }
}
