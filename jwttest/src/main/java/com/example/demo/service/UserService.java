package com.example.demo.service;

import com.example.demo.model.User;
import com.example.demo.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class UserService {

    @Autowired
    private UserRepository repo;

    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public User register(String username, String rawPassword) {
        String encodedPwd = encoder.encode(rawPassword);
        User user = new User();
        user.setUsername(username);
        user.setPassword(encodedPwd); // 🔥 最重要的一行！
        return repo.save(user);
    }


    public Optional<User> findByUsername(String username) {
        return repo.findByUsername(username);
    }

    public boolean verifyPassword(String rawPwd, String encodedPwd) {
        return encoder.matches(rawPwd, encodedPwd);
    }
}
