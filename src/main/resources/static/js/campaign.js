$(document).ready(function () {
  // 1. 「全選択」する
  $('#all_check').on('click', function () {
    $(".row_check").prop('checked', this.checked);
  });
  // 2. 「全選択」以外のチェックボックスがクリックされたら、
  $(".row_check").on('click', function () {
    var checkBox = ".row_check";
    var boxCount = $(checkBox).length; //全チェックボックスの数を取得
    var checked = $(checkBox + ':checked').length; //チェックされているチェックボックスの数を取得
    if (checked === boxCount) {
      $('#all_check').prop('checked', true);
    } else {
      $('#all_check').prop('checked', false);
    }
  });
});
