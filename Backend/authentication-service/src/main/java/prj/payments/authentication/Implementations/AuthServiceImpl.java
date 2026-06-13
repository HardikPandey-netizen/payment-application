package prj.payments.authentication.Implementations;

import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import prj.payments.authentication.DTOs.AuthResponse;
import prj.payments.authentication.DTOs.LoginRequest;
import prj.payments.authentication.DTOs.RegisterRequest;
import prj.payments.authentication.Entity.AppUser;
import prj.payments.authentication.Repositories.UserRepository;
import prj.payments.authentication.Security.JwtService;
import prj.payments.authentication.Services.AuthService;

@Service
@RequiredArgsConstructor
public class AuthServiceImpl implements AuthService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;


    @Override
    public AuthResponse login(LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        loginRequest.email(),
                        loginRequest.password()
                )
        );
        AppUser user = userRepository.findByEmail(authentication.getName());
        String token = jwtService.generateToken(user);

        return new AuthResponse(
                token,
                user.getId(),
                user.getUsername(),
                user.getEmail(),
                user.getRole().name()
        );
    }

    @Override
    public AuthResponse register(RegisterRequest registerRequest) {
        if(userRepository.existsByUsername(registerRequest.username())){
            throw new UsernameNotFoundException("User is already logged in");
        }
        if(userRepository.existsByEmail(registerRequest.email())){
            throw new IllegalArgumentException("Email is already registered");
        }
        AppUser user = new AppUser();
        user.setUsername(registerRequest.username());
        user.setEmail(registerRequest.email());
        user.setPassword(passwordEncoder.encode(registerRequest.password()));
        AppUser saved = userRepository.save(user);
        String token = jwtService.generateToken(saved);
        return new AuthResponse(
                token,
                saved.getId(),
                saved.getUsername(),
                saved.getEmail(),
                saved.getRole().name()
        );
    }


}
