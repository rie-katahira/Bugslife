$(document).ready(function () {
  // 全チェック切り替え
  $("#all_check").on("click", function () {
    // 各行のチェックボックスの切り替え
    $(".row_check").prop("checked", this.checked);
  });

  // 各行のチェック切り替え
  $(".row_check").on("click", function () {
    var checkBox = ".row_check";
    var boxCount = $(checkBox).length; //全チェックボックスの数を取得
    var checked = $(checkBox + ":checked").length; //チェックされているチェックボックスの数を取得
    if (checked === boxCount) {
      $("#all_check").prop("checked", true);
    } else {
      $("#all_check").prop("checked", false);
    }
  });
});
