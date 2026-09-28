package itmo.config;

import java.nio.charset.StandardCharsets;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;

@Configuration
public class DemoData {
    @Bean
    CommandLineRunner initializeData(JdbcTemplate jdbc, PasswordEncoder encoder,
                                    @Value("${app.demo.login}") String login,
                                    @Value("${app.demo.password}") String password,
                                    @Value("${app.demo.other-login}") String otherLogin,
                                    @Value("${app.demo.other-password}") String otherPassword) {
        validateCredentials(login, password);
        if (!otherPassword.isBlank()) {
            validateCredentials(otherLogin, otherPassword);
            if (login.equals(otherLogin)) {
                throw new IllegalArgumentException("Demo users must have different logins");
            }
        }
        String hash = encoder.encode(password);
        String otherHash = otherPassword.isBlank() ? null : encoder.encode(otherPassword);
        return args -> {
            jdbc.update("INSERT INTO app_user (username, password_hash) VALUES (?, ?)", login, hash);
            if (otherHash != null) {
                jdbc.update("INSERT INTO app_user (username, password_hash) VALUES (?, ?)", otherLogin, otherHash);
            }
            jdbc.update("INSERT INTO note (id, owner, content) VALUES (?, ?, ?)",
                    UUID.randomUUID(), login, "Первая защищённая заметка");
        };
    }

    private static void validateCredentials(String login, String password) {
        if (!login.matches("[a-zA-Z0-9_-]{1,64}")) {
            throw new IllegalArgumentException("Demo login: 1-64 letters, digits, underscores or hyphens");
        }
        if (password.length() < 12 || password.getBytes(StandardCharsets.UTF_8).length > 72) {
            throw new IllegalArgumentException("Demo password: at least 12 characters, at most 72 UTF-8 bytes");
        }
    }
}
