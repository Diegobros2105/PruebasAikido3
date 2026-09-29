/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.mailbox;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Data transfer object for incoming email creation requests. This DTO excludes the id field to
 * prevent mass assignment attacks where an attacker could overwrite existing emails by supplying
 * an existing id value.
 */
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class EmailRequest {

  @NotBlank private String contents;

  @NotBlank private String sender;

  @NotBlank private String title;

  @NotBlank private String recipient;
}
