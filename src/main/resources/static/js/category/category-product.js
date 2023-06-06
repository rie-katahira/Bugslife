$(document).ready(function () {
  let categoryId = document.getElementById("categoryId").getAttribute("val");
  let action = document.getElementById("action").getAttribute("val");

  $.ajax({
    url: "/api/category/" + categoryId,
    type: "GET",
    dataType: "json",
  })
    .done(function (data) {
      var categoryProducts = data;
      // チェックボックスにチェックを入れる処理
      categoryProducts.forEach(function (categoryProduct) {
        $("#checkbox-" + categoryProduct.productId).prop("checked", true);
      });
    })
    .fail(function () {
      // APIコールが失敗した場合の処理
      console.log("APIコールが失敗しました。");
    });

  $("#update-button").click(function () {
    var checkedIds = $(".form-check-input:checked")
      .map(function () {
        return this.value;
      })
      .get();

    // 作成更新時に紐付けが存在しない場合はスキップ
    if (action == "true") {
      if (!validation(checkedIds)) {
        return false;
      }
    }

    let postData = {
      productIds: checkedIds,
    };

    $.ajax({
      url: "/api/categories/" + categoryId + "/updateCategoryProduct",
      type: "POST",
      dataType: "text",
      contentType: "application/json",
      data: postData,
    }).done(function (data) {
      $("#success-message").text(data).show().fadeOut(3000);
    });
  });

  validation = function (checkedIds) {
    if (checkedIds.length == 0) {
      $("#error-message")
        .text(
          "商品を選択して更新か、不要な場合はカテゴリー一覧を選択して下さい。"
        )
        .show()
        .fadeOut(3000);
      return false;
    }
    return true;
  };
});
