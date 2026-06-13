package prj.payments.authentication.Services;

import prj.payments.authentication.DTOs.AuthResponse;
import prj.payments.authentication.DTOs.LoginRequest;
import prj.payments.authentication.DTOs.RegisterRequest;

public interface AuthService {
    AuthResponse login(LoginRequest loginRequest);
    AuthResponse register(RegisterRequest registerRequest);
}
