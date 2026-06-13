package prj.payments.authentication.DTOs;

public record UserResponse(
        Long id,
        String username,
        String password,
        String role
) {}
