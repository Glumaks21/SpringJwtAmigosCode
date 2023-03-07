package com.alibou.security.auth;

public record RegisterRequest(
        String firstname,
        String lastname,
        String email,
        String password
) {
}
