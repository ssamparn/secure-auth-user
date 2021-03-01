package com.edgeservice.secureauthuser.interceptor.filter;

import com.edgeservice.secureauthuser.interceptor.user.UserPrincipal;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class TokenBasedAuthentication extends AbstractAuthenticationToken {

    private final String token;
    private final UserPrincipal principal;

    public TokenBasedAuthentication(final String token, final UserPrincipal principal, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.token = token;
        this.principal = principal;
    }

    @Override
    public Object getCredentials() {
        return token;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
