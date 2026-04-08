package com.programacion4.unidad5ej7.auth.dtos.response;

public record AuthResponseDto(
    String accessToken,
    String refreshToken, 
    String tokenType
) {
}
