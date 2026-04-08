package com.programacion4.unidad5ej7.auth.controllers;

import com.programacion4.unidad5ej7.auth.dtos.request.LoginRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.request.RefreshTokenRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.request.RegisterRequestDto;
import com.programacion4.unidad5ej7.auth.dtos.response.AuthResponseDto;
import com.programacion4.unidad5ej7.auth.services.impl.AuthService;
import com.programacion4.unidad5ej7.auth.services.interfaces.IAuthService;
import com.programacion4.unidad5ej7.config.BaseResponse;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.AllArgsConstructor;

@RestController
@RequestMapping("/auth")
@AllArgsConstructor
public class AuthController {

	private final IAuthService authService;

	/**
	 * Registro HTTP: {@code @Valid} dispara validación Bean Validation antes del
	 * servicio; {@link AuthService#register}
	 * persiste el usuario codificado o propaga {@code UserAlreadyExistsException}
	 * (409) vía {@code GlobalExceptionHandler}.
	 * No se devuelve contraseña ni entidad interna: solo confirmación en
	 * {@link BaseResponse}.
	 */
	@PostMapping("/register")
	public ResponseEntity<BaseResponse<Void>> register(@Valid @RequestBody RegisterRequestDto request) {
		authService.register(request);
		return ResponseEntity.status(HttpStatus.CREATED)
				.body(BaseResponse.ok(null, "Usuario registrado correctamente"));
	}

	/**
	 * Login HTTP: validación del body, luego {@link AuthService#login} usa el
	 * {@code AuthenticationManager} y emite el JWT
	 * dentro de {@link AuthResponse}; credenciales inválidas se traducen a 401 sin
	 * detallar la causa concreta.
	 */
	@PostMapping("/login")
	public ResponseEntity<BaseResponse<AuthResponseDto>> login(@Valid @RequestBody LoginRequestDto request) {
		AuthResponseDto body = authService.login(request);
		return ResponseEntity.ok(BaseResponse.ok(body, "Autenticación correcta"));
	}

	@PostMapping("/refresh")
	public AuthResponseDto refresh(@RequestBody RefreshTokenRequestDto request) {
		return authService.refresh(request.refreshToken());
	}
}
