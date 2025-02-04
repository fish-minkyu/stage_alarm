package com.example.stagealarm.order.service;

import com.example.stagealarm.facade.AuthenticationFacade;
import com.example.stagealarm.item.entity.Item;
import com.example.stagealarm.item.entity.Status;
import com.example.stagealarm.item.repo.ItemRepository;
import com.example.stagealarm.item.service.ItemService;
import com.example.stagealarm.order.dto.ItemOrderDto;
import com.example.stagealarm.order.entity.ItemOrder;
import com.example.stagealarm.order.repo.OrderRepository;
import com.example.stagealarm.toss.dto.PaymentCancelDto;
import com.example.stagealarm.toss.dto.PaymentConfirmDto;
import com.example.stagealarm.toss.service.TossHttpService;
import com.example.stagealarm.user.entity.UserEntity;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class OrderService {
    private final TossHttpService tossService;
    private final OrderRepository orderRepository;
    private final ItemRepository itemRepository;
    private final ItemService itemService;
    private final AuthenticationFacade facade;



    // 아이디로 주문 찾기(관리자)
    public ItemOrderDto searchById(Long id) {
        ItemOrder itemOrder = orderRepository.findById(id).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND)
        );
        return ItemOrderDto.fromEntity(itemOrder);
    }

    // 주문 상태 업데이트(관리자)
    @Transactional
    public ItemOrderDto update(Long id, Status status) {

        ItemOrder itemOrder = orderRepository.findById(id).orElseThrow(
                () -> new ResponseStatusException(HttpStatus.NOT_FOUND)
        );
        itemOrder.setStatus(status);
        return ItemOrderDto.fromEntity(itemOrder);
    }

    // 주문 삭제(관리자)
    @Transactional
    public void delete(Long id) {
        orderRepository.deleteById(id);
    }

    // 모든 주문 조회(관리자)
    public List<ItemOrderDto> readAll() {
        return orderRepository.findAll().stream()
                .map(ItemOrderDto::fromEntity)
                .collect(Collectors.toList());
    }

    // 주문 완료
    @Transactional
    public Object confirmPayment(PaymentConfirmDto dto){
        // 구매자가 누구인지
        UserEntity userEntity = facade.getUserEntity();

        Object tossPaymentObj = tossService.confirmPayment(dto);
        log.info(tossPaymentObj.toString());
        // 사용자가 결제한 물품 + 결제 정보에 대한 내용을 DB에 저장한다.
        // 1. 결제한 물품 정볼를 응답 Body 에서 찾는다
        String orderName = ((LinkedHashMap<?, ?>) tossPaymentObj).get("orderName").toString();
        Object totalAmountObj = ((LinkedHashMap<?, ?>) tossPaymentObj).get("totalAmount");
        Integer totalAmount = null;

        if (totalAmountObj instanceof Integer) {
            totalAmount = (Integer) totalAmountObj;
        }

        // 2. orderName 에서 itemId를 회수하고, 그에 해당하는 Item 엔티티를 조회한다.
        Long itemId = Long.parseLong(orderName.split("-")[0]);
        Item item = itemRepository.findById(itemId)
                .orElseThrow(
                        () -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR)
                );


        Integer quantity = (totalAmount / item.getPrice());

        // 아이템 수량 업데이트
        // 주문시에는 음수
        itemService.updateAmount(itemId, -quantity);


        // 3. Item 엔티티를 바탕으로 ItemOrder 를 만들자
        return ItemOrderDto.fromEntity(orderRepository.save(ItemOrder.builder()
                .user(userEntity)
                .item(item)
                .tossPaymentKey(dto.getPaymentKey())
                .tossOrderId(dto.getOrderId())
                .totalPrice(totalAmount)
                .amount(quantity)
                .status(Status.COMPLETED)
                .build()));
    }

    // readTossPayment
    public Object readTossPayment(Long id){
        // 1. id를 가지고 주문정보를 조회한다.
        ItemOrder itemOrder = orderRepository.findById(id)
                .orElseThrow(
                        () -> new ResponseStatusException(HttpStatus.NOT_FOUND)
                );
        // 2. 주문정보에 포함된 결제 정보키(paymentKey)를 바탕으로
        // Toss 에 요청을 보내 결제 정보를 받는다.
        Object response = tossService.getPayment(itemOrder.getTossPaymentKey());
        log.info(response.toString());

        // 3. 해당 결제 정보를 반환한다.
        return response;
    }

    // cancelPayment
    @Transactional
    public Object cancelPayment(
            Long id,
            PaymentCancelDto dto
    ){
        UserEntity userEntity = facade.getUserEntity();
        // 1. 취소할 주문을 찾는다.
        ItemOrder itemOrder = orderRepository.findById(id)
                .orElseThrow(
                        () -> new ResponseStatusException(HttpStatus.NOT_FOUND)
                );
        // 내주문만 취소할수 있다.
        if(!userEntity.getAuthorities().equals("ROLE_ADMIN") &&
                !userEntity.getId().equals(itemOrder.getUser().getId())){
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }

        // 2. 주문정보를 갱신한다.
        itemOrder.setStatus(Status.CANCEL);

        // 3. 아이템 수량을 업데이트 한다
        itemService.updateAmount(itemOrder.getItem().getId(), itemOrder.getAmount());
        // 4. 취소후 결과를 응답한다.
        return tossService.cancelPayment(itemOrder.getTossPaymentKey(), dto);

    }

    public List<ItemOrderDto> searAllByUserId() {
        UserEntity userEntity = facade.getUserEntity();

        return orderRepository.findByUserIdOrderByIdDesc(userEntity.getId())
                .stream()
                .map(ItemOrderDto::fromEntity)
                .collect(Collectors.toList());
    }
}
