package com.metacoding.spring_oauth_oidc.user;

import java.time.LocalDateTime;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_tb")
public class User {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Integer id;

    @Column(nullable = false, unique = true, length = 40)
    private String username;

    @Column(nullable = false, length = 100)
    private String password;

    @Column(nullable = false, unique = true, length = 80)
    private String email;

    @Column(length = 30)
    private String provider;

    @Column(name = "provider_id", length = 100)
    private String providerId;

    @Column(name = "created_at")
    private LocalDateTime createdAt;

    public void updateEmail(String newEmail) {
        if (newEmail != null && !newEmail.isBlank() && !newEmail.equals(this.email)) {
            this.email = newEmail;
        }
    }

    public void updateUsername(String newUsername) {
        if (newUsername != null && !newUsername.isBlank() && !newUsername.equals(this.username)) {
            this.username = newUsername;
        }
    }

    public void updateProviderInfo(String provider, String providerId) {
        if (provider != null && !provider.isBlank()) {
            this.provider = provider;
        }
        if (providerId != null && !providerId.isBlank()) {
            this.providerId = providerId;
        }
    }
}
