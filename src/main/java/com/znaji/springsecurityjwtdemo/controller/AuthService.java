package com.znaji.springsecurityjwtdemo.controller;

import com.znaji.springsecurityjwtdemo.config.JwtService;
import com.znaji.springsecurityjwtdemo.user.Role;
import com.znaji.springsecurityjwtdemo.user.User;
import com.znaji.springsecurityjwtdemo.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;

    public AuthResponse singin(SigningRequest signingRequest) {
        final User user = User.builder()
                .firstName(signingRequest.getFirstName())
                .lastName(signingRequest.getLastName())
                .email(signingRequest.getEmail())
                .password(passwordEncoder.encode(signingRequest.getPassword()))
                .role(Role.USER)
                .build();
        userRepository.save(user);
        return AuthResponse.builder()
                .token(jwtService.generateToken(user))
                .build();
    }

    public AuthResponse singup(SignupRequest signupRequest) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signupRequest.getEmail(),
                        signupRequest.getPassword()
                )
        );
        final User user = userRepository.findByEmail(signupRequest.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        return AuthResponse.builder()
                .token(jwtService.generateToken(user))
                .build();
    }
}
