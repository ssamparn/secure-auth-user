package com.edgeservice.secureauthuser.interceptor.user;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.ArrayList;
import java.util.List;

@Data
public class UserPrincipal {

    private String authTicket;
    private String authSessionId;
    private String authUserId;
    private String authUserType;
    private String authUserLevel;
    private String siebelCustomerRelationId;
    private String siebelUserRelationId;
    private String edoKlid;
    private String edoAgreementId;
    private String edoUserId;
    private List<String> sources = new ArrayList<>();

    @JsonCreator
    public UserPrincipal(@JsonProperty(required = true, value = "edoUserId") String edoUserId) {
        this.edoUserId = edoUserId;
    }

}
