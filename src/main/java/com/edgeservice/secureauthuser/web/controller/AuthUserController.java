package com.edgeservice.secureauthuser.web.controller;

import com.edgeservice.secureauthuser.interceptor.filter.TokenBasedAuthentication;
import com.edgeservice.secureauthuser.interceptor.user.UserPrincipal;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/business")
public class AuthUserController {

    @GetMapping("/payment-order-batches/{encryptedBatchId}")
    public ResponseEntity<Map<String, String>> getUserInfo(@PathVariable(name = "encryptedBatchId") String encryptedBatchId,
                                                           @RequestHeader(value = "x-auth-user") String xAuthHeader) {

        TokenBasedAuthentication authToken = (TokenBasedAuthentication) SecurityContextHolder.getContext().getAuthentication();

        UserPrincipal userPrincipal = (UserPrincipal) authToken.getPrincipal();

        return new ResponseEntity(Map.of(userPrincipal.getEdoKlid(), authToken.getCredentials()), HttpStatus.OK);
    }
}
