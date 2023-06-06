package com.example.controller;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.test.context.support.WithMockUser;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import jakarta.servlet.ServletException;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Optional;

import org.hamcrest.beans.SamePropertyValuesAs;

import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.flash;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;

import com.example.constants.Message;
import com.example.constants.PaymentType;
import com.example.enums.OrderStatus;
import com.example.enums.PaymentMethod;
import com.example.enums.PaymentStatus;
import com.example.form.OrderForm;
import com.example.model.Order;
import com.example.model.OrderPayment;
import com.example.model.OrderProduct;
import com.example.model.Product;
import com.example.service.OrderService;
import com.example.service.ProductService;

import io.florianlopes.spring.test.web.servlet.request.MockMvcRequestBuilderUtils;

/**
 * OrderControllerのテストクラス
 */
@SpringBootTest
@AutoConfigureMockMvc
@WithMockUser
public class OrderControllerTests {
	@Autowired
	private OrderService orderService;

	@Autowired
	private ProductService productService;

	/**
	 * get indexのテスト
	 */
	@Test
	public void getIndexTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/orders"))
				.andExpect(status().isOk()).andExpect(view().name("order/index"))
				.andExpect(model().attributeExists("listOrder"));
	}

	/**
	 * get showのテスト
	 */
	@Test
	public void getShowTest(@Autowired MockMvc mvc) throws Exception {
		Order order = new Order();
		order.setCustomerId(42);
		order.setDiscount(42.0);
		order.setShipping(42.0);
		order.setTax(42.0);
		order.setTotal(42.0);
		order.setGrandTotal(42.0 * 2);
		order.setStatus(OrderStatus.ORDERED);
		order.setPaymentMethod(PaymentMethod.CREDIT_CARD);
		order.setPaymentStatus(PaymentStatus.UNPAID);
		order.setPaid(0.0);
		order.setNote("test");
		order.setOrderPayments(new ArrayList<OrderPayment>());
		order.setOrderProducts(new ArrayList<OrderProduct>());
		orderService.save(order);

		mvc.perform(MockMvcRequestBuilders.get("/orders/" + order.getId()))
				.andExpect(status().isOk())
				.andExpect(view().name("order/show"))
				.andExpect(model().attributeExists("order"));
	}

	/**
	 * get creteのテスト
	 */
	@Test
	public void getCreateTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.get("/orders/new"))
				.andExpect(status().isOk())
				.andExpect(view().name("order/create"))
				.andExpect(model().attributeExists("order"))
				.andExpect(model().attributeExists("products"));
	}

	/**
	 * post create 失敗 テスト
	 */
	@Test
	public void postCreateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.post("/orders").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/orders"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * post create 成功 テスト
	 */
	@Test
	public void postCreateValidTest(@Autowired MockMvc mvc) throws Exception {
		Product product = new Product();
		product.setName("test");
		product.setCode("42");
		product.setWeight(42);
		product.setHeight(42);
		product.setPrice(42);
		product.setTaxType(1);
		productService.save(product);
		mvc.perform(
				MockMvcRequestBuilders.post("/orders")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("customerId", "1")
						.param("discount", "0.0")
						.param("shipping", "0.0")
						.param("paymentMethod", PaymentMethod.CREDIT_CARD)
						.param("note", "test")
						.param("orderProducts[0].productId", product.getId().toString())
						.param("orderProducts[0].discount", "0.0")
						.param("orderProducts[0].quantity", "1"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrlPattern("/orders/{id:[0-9]+}"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_INSERT));
	}

	/**
	 * get update 失敗 テスト
	 */
	@Test
	public void getUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc.perform(MockMvcRequestBuilders.get("/orders/999/edit")));
	}

	/**
	 * get update 成功テスト
	 */
	@Test
	public void getUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Order order = new Order();
		order.setCustomerId(42);
		order.setDiscount(42.0);
		order.setShipping(42.0);
		order.setTax(42.0);
		order.setTotal(42.0);
		order.setGrandTotal(42.0 * 2);
		order.setStatus(OrderStatus.ORDERED);
		order.setPaymentMethod(PaymentMethod.CREDIT_CARD);
		order.setPaymentStatus(PaymentStatus.UNPAID);
		order.setPaid(0.0);
		order.setNote("test");
		order.setOrderPayments(new ArrayList<OrderPayment>());
		order.setOrderProducts(new ArrayList<OrderProduct>());

		orderService.save(order);

		mvc.perform(MockMvcRequestBuilders.get("/orders/" + order.getId() + "/edit"))
				.andExpect(status().isOk())
				.andExpect(view().name("order/form"))
				.andExpect(model().attribute("order",
						SamePropertyValuesAs.samePropertyValuesAs(order, "orderPayments", "orderProducts")));
	}

	/**
	 * put update 失敗 テスト
	 */
	@Test
	public void putUpdateInValidTest(@Autowired MockMvc mvc) throws Exception {
		mvc.perform(MockMvcRequestBuilders.put("/orders").with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/orders"))
				.andExpect(flash().attribute("error", Message.MSG_ERROR));
	}

	/**
	 * put update 成功 テスト
	 */
	@Test
	public void putUpdateValidTest(@Autowired MockMvc mvc) throws Exception {
		Order order = new Order();
		order.setCustomerId(42);
		order.setDiscount(42.0);
		order.setShipping(42.0);
		order.setTax(42.0);
		order.setTotal(42.0);
		order.setGrandTotal(168.0);
		order.setStatus(OrderStatus.ORDERED);
		order.setPaymentMethod(PaymentMethod.CREDIT_CARD);
		order.setPaymentStatus(PaymentStatus.UNPAID);
		order.setPaid(0.0);
		order.setNote("test");

		orderService.save(order);

		mvc.perform(
				MockMvcRequestBuilders.put("/orders")
						.with(SecurityMockMvcRequestPostProcessors.csrf())
						.param("id", order.getId().toString())
						.param("customerId", "1")
						.param("discount", "42.0")
						.param("shipping", "42.0")
						.param("tax", "42.0")
						.param("total", "42.0")
						.param("grandTotal", "168.0")
						.param("status", OrderStatus.SHIPPED)
						.param("paymentMethod", PaymentMethod.CREDIT_CARD)
						.param("paymentStatus", PaymentStatus.PAID)
						.param("paid", "168.0")
						.param("note", "test"))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/orders/" + order.getId()))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_UPDATE));

		Optional<Order> order2 = orderService.findOne(order.getId());
		Assertions.assertEquals(OrderStatus.SHIPPED, order2.get().getStatus());
		Assertions.assertEquals(168.0, order2.get().getPaid());
		Assertions.assertEquals(PaymentStatus.PAID, order2.get().getPaymentStatus());

	}

	/**
	 * delete 失敗 テスト
	 */
	@Test
	public void deleteInValidTest(@Autowired MockMvc mvc) throws Exception {
		Assertions.assertThrows(ServletException.class, () -> mvc
				.perform(MockMvcRequestBuilders.delete("/orders/999").with(SecurityMockMvcRequestPostProcessors.csrf())));
	}

	/**
	 * delete 成功 テスト
	 */
	@Test
	public void deleteValidTest(@Autowired MockMvc mvc) throws Exception {
		Order order = new Order();
		order.setCustomerId(42);
		order.setDiscount(42.0);
		order.setShipping(42.0);
		order.setTax(42.0);
		order.setTotal(42.0);
		order.setGrandTotal(42.0 * 2);
		order.setStatus(OrderStatus.ORDERED);
		order.setPaymentMethod(PaymentMethod.CREDIT_CARD);
		order.setPaymentStatus(PaymentStatus.UNPAID);
		order.setPaid(0.0);
		order.setNote("test");

		orderService.save(order);

		mvc.perform(
				MockMvcRequestBuilders.delete("/orders/" + order.getId()).with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/orders"))
				.andExpect(flash().attribute("success", Message.MSG_SUCESS_DELETE));

		Optional<Order> order2 = orderService.findOne(order.getId());
		Assertions.assertFalse(order2.isPresent());
	}

	/**
	 * createPayment 成功 テスト
	 */
	@Test
	public void createPaymentValidTest(@Autowired MockMvc mvc) throws Exception {
		Order order = new Order();
		order.setCustomerId(42);
		order.setDiscount(42.0);
		order.setShipping(42.0);
		order.setTax(42.0);
		order.setTotal(42.0);
		order.setGrandTotal(42.0 * 2);
		order.setStatus(OrderStatus.ORDERED);
		order.setPaymentMethod(PaymentMethod.CREDIT_CARD);
		order.setPaymentStatus(PaymentStatus.UNPAID);
		order.setPaid(0.0);
		order.setNote("test");
		order.setOrderPayments(new ArrayList<OrderPayment>());
		order.setOrderProducts(new ArrayList<OrderProduct>());

		orderService.save(order);

		var params = new OrderForm.CreatePayment();
		params.setOrderId(order.getId());
		params.setPaid(42.0);
		params.setType(PaymentType.COMPLETED);
		params.setMethod(PaymentMethod.CREDIT_CARD);
		params.setPaidAt(new Timestamp(System.currentTimeMillis()));

		mvc.perform(
				MockMvcRequestBuilderUtils.postForm("/orders/" + order.getId() + "/payments", params)
						.with(SecurityMockMvcRequestPostProcessors.csrf()))
				.andExpect(status().isFound())
				.andExpect(redirectedUrl("/orders/" + order.getId()))
				.andExpect(flash().attribute("success", "支払い情報を更新しました"));

		Optional<Order> order2 = orderService.findOne(order.getId());
		Assertions.assertEquals(42.0, order2.get().getPaid());
		Assertions.assertEquals(PaymentStatus.PARTIALLY_PAID, order2.get().getPaymentStatus());
	}
}
