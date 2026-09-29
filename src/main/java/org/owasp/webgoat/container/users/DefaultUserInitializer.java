/*
 * SPDX-FileCopyrightText: Copyright © 2025 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.****.container.users;

import java.security.SecureRandom;
import lombok.AllArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;

/**
 * Seeds default accounts on first startup so that the platform is immediately usable without manual
 * database intervention.
 *
 * <p>If the users already exist, their credentials are left untouched, making this bean idempotent
 * across restarts.
 *
 * <p>The administrator account can be configured via environment variables {@code
 * WEBGOAT_ADMIN_USERNAME} and {@code WEBGOAT_ADMIN_PASSWORD}. If not provided, a random password
 * is generated on first creation and logged to the console. Existing administrator credentials are
 * never overwritten on restart.
 */
@Component
@AllArgsConstructor
@Slf4j
public class DefaultUserInitializer implements ApplicationRunner {

  private static final String DEFAULT_ADMIN_USERNAME = "****-admin";
  private static final String DEFAULT_USER_USERNAME = "****-user";
  private static final String DEFAULT_USER_PASSWORD = "****";
  private static final String ADMIN_USERNAME_ENV = "WEBGOAT_ADMIN_USERNAME";
  private static final String ADMIN_PASSWORD_ENV = "WEBGOAT_ADMIN_PASSWORD";
  private static final String CHARS =
      "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*";
  private static final int GENERATED_PASSWORD_LENGTH = 16;
  private static final SecureRandom SECURE_RANDOM = new SecureRandom();

  private final UserRepository userRepository;
  private final UserService userService;
  private final Environment environment;

  @Override
  public void run(ApplicationArguments args) {
    // 1. Seed the default admin
    String adminUsername =
        environment.getProperty(ADMIN_USERNAME_ENV, String.class, DEFAULT_ADMIN_USERNAME);

    if (!userRepository.existsByUsername(adminUsername)) {
      // Admin does not exist: create it with environment-provided or generated credentials
      String adminPassword = environment.getProperty(ADMIN_PASSWORD_ENV, String.class, null);
      boolean passwordWasGenerated = false;

      if (adminPassword == null || adminPassword.isBlank()) {
        adminPassword = generateSecurePassword();
        passwordWasGenerated = true;
      }

      userRepository.save(new WebGoatUser(adminUsername, adminPassword, WebGoatUser.ROLE_ADMIN));

      if (passwordWasGenerated) {
        log.warn(
            "╔═══════════════════════════════════════════════════════════════════════════════╗");
        log.warn(
            "║ GENERATED ADMINISTRATOR CREDENTIALS                                           ║");
        log.warn(
            "╠═══════════════════════════════════════════════════════════════════════════════╣");
        log.warn("║ Username: {:<68}║", adminUsername);
        log.warn("║ Password: {:<68}║", adminPassword);
        log.warn(
            "╠═══════════════════════════════════════════════════════════════════════════════╣");
        log.warn(
            "║ This password was randomly generated because no environment variable was set. ║");
        log.warn(
            "║ To use a custom password, set WEBGOAT_ADMIN_PASSWORD before startup.         ║");
        log.warn(
            "║ This message will not be shown again after restart.                          ║");
        log.warn(
            "╚═══════════════════════════════════════════════════════════════════════════════╝");
      } else {
        log.info(
            "Created administrator account '{}' with environment-provided credentials.",
            adminUsername);
      }
    } else {
      log.info(
          "Administrator account '{}' already exists. Preserving existing credentials.",
          adminUsername);
    }

    // 2. Seed the default regular user
    if (!userRepository.existsByUsername(DEFAULT_USER_USERNAME)) {
      // Use UserService here because it properly provisions lessons and progress trackers
      // for a normal user, which is required for them to actually play the game.
      userService.addUser(DEFAULT_USER_USERNAME, DEFAULT_USER_PASSWORD);
      log.info(
          "Created default regular user account '{}' and provisioned lessons.",
          DEFAULT_USER_USERNAME);
    } else {
      log.info(
          "Default regular user account '{}' already exists. Skipping initialization.",
          DEFAULT_USER_USERNAME);
    }
  }

  private static String generateSecurePassword() {
    StringBuilder sb = new StringBuilder(GENERATED_PASSWORD_LENGTH);
    for (int i = 0; i < GENERATED_PASSWORD_LENGTH; i++) {
      sb.append(CHARS.charAt(SECURE_RANDOM.nextInt(CHARS.length())));
    }
    return sb.toString();
  }
}
