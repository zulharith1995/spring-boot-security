package com.example.demo.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.security.Keys;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/* sometimes a filter can be invokes more than once but OncePerRequestFilter makes sure that
* this filter will be invoked only once per request. */

/* everytime we create a filter, we need to register in the ApplicationSecurityConfig class's config method */

public class JwtTokenVerifier extends OncePerRequestFilter {

    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        //String authorizationHeader = request.getHeader("Authorization");  // previous implementation
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        if (Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith(jwtConfig.getTokenPrefix())) {
            filterChain.doFilter(request, response);    // request will be rejected
            return;
        }

        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try {
            //String secretKey = "securesecuresecuresecuresecuresecuresecuresecure";    // previous implementation

            Jws<Claims> claimsJws = Jwts.parserBuilder()
                    .setSigningKey(secretKey)
                    .build()
                    .parseClaimsJws(token);
            Claims body = claimsJws.getBody();
            String username = body.getSubject();

            List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");
            /* now we have the authorities we can go ahead and tell spring security that from this point onwards
            * this user can be authenticated */

            Set<SimpleGrantedAuthority> simpleGrantedAuthorities = authorities.stream()
                    .map(m -> new SimpleGrantedAuthority(m.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthorities
            );

            SecurityContextHolder.getContext().setAuthentication(authentication); /* at this point of time, we can say that the client sent the token is authenticated */

        } catch (JwtException jwtException) {
            throw new IllegalStateException(String.format("Token %s can not be trusted", token));
        }

        filterChain.doFilter(request, response);
        /* (V.V.I) after executing it's own logic, each filter should pass the request and response to it's next filter
         * until the request reaches to the controller */
    }
}
