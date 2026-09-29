/*
 * SPDX-FileCopyrightText: Copyright © 2023 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.net.URI;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;

class WebWolfTraceRepositoryTest {

  @Test
  @DisplayName("When a user hits a file upload it should be recorded")
  void shouldAddFilesRequest() {
    HttpExchange httpExchange = mock();
    HttpExchange.Request request = mock();
    when(httpExchange.getRequest()).thenReturn(request);
    when(request.getUri()).thenReturn(URI.create("http://localhost:9090/files/test1234/test.jpg"));
    WebWolfTraceRepository repository = new WebWolfTraceRepository();

    repository.add(httpExchange);

    Assertions.assertThat(repository.findAll()).hasSize(1);
  }

  @Test
  @DisplayName("When a user hits file upload page ('/files') it should be recorded")
  void shouldAddNotAddFilesRequestOverview() {
    HttpExchange httpExchange = mock();
    HttpExchange.Request request = mock();
    when(httpExchange.getRequest()).thenReturn(request);
    when(request.getUri()).thenReturn(URI.create("http://localhost:9090/files"));
    WebWolfTraceRepository repository = new WebWolfTraceRepository();

    repository.add(httpExchange);

    Assertions.assertThat(repository.findAll()).hasSize(0);
  }

  @Test
  @DisplayName("Users should only see their own traces")
  void shouldIsolateTracesByUser() {
    WebWolfTraceRepository repository = new WebWolfTraceRepository();

    // Add trace for user1
    HttpExchange exchange1 = mock();
    HttpExchange.Request request1 = mock();
    HttpExchange.Principal principal1 = mock();
    when(exchange1.getRequest()).thenReturn(request1);
    when(exchange1.getPrincipal()).thenReturn(principal1);
    when(principal1.getName()).thenReturn("user1");
    when(request1.getUri()).thenReturn(URI.create("http://localhost:9090/landing?text=secret1"));
    repository.add(exchange1);

    // Add trace for user2
    HttpExchange exchange2 = mock();
    HttpExchange.Request request2 = mock();
    HttpExchange.Principal principal2 = mock();
    when(exchange2.getRequest()).thenReturn(request2);
    when(exchange2.getPrincipal()).thenReturn(principal2);
    when(principal2.getName()).thenReturn("user2");
    when(request2.getUri()).thenReturn(URI.create("http://localhost:9090/landing?text=secret2"));
    repository.add(exchange2);

    // Verify user1 only sees their own trace
    Assertions.assertThat(repository.findAllForUser("user1")).hasSize(1);
    Assertions.assertThat(repository.findAllForUser("user1").get(0)).isEqualTo(exchange1);

    // Verify user2 only sees their own trace
    Assertions.assertThat(repository.findAllForUser("user2")).hasSize(1);
    Assertions.assertThat(repository.findAllForUser("user2").get(0)).isEqualTo(exchange2);

    // Verify both traces exist in the repository
    Assertions.assertThat(repository.findAll()).hasSize(2);
  }

  @Test
  @DisplayName("Unauthenticated requests without user context should not be visible to any user")
  void shouldNotShowUnauthenticatedRequestsWithoutUserContext() {
    WebWolfTraceRepository repository = new WebWolfTraceRepository();

    // Add unauthenticated trace without user context (e.g., /landing?text=...)
    HttpExchange exchange = mock();
    HttpExchange.Request request = mock();
    when(exchange.getRequest()).thenReturn(request);
    when(exchange.getPrincipal()).thenReturn(null);
    when(request.getUri()).thenReturn(URI.create("http://localhost:9090/landing?text=secret"));
    repository.add(exchange);

    // Verify no user can see this trace
    Assertions.assertThat(repository.findAllForUser("user1")).isEmpty();
    Assertions.assertThat(repository.findAllForUser("user2")).isEmpty();

    // But it exists in the global list (for backward compatibility)
    Assertions.assertThat(repository.findAll()).hasSize(1);
  }

  @Test
  @DisplayName("Should extract username from uniqueCode parameter")
  void shouldExtractUsernameFromUniqueCode() {
    WebWolfTraceRepository repository = new WebWolfTraceRepository();

    // Add trace with uniqueCode (reversed username)
    HttpExchange exchange = mock();
    HttpExchange.Request request = mock();
    when(exchange.getRequest()).thenReturn(request);
    when(exchange.getPrincipal()).thenReturn(null);
    when(request.getUri())
        .thenReturn(URI.create("http://localhost:9090/landing?uniqueCode=1resu"));
    repository.add(exchange);

    // Verify user1 (reversed: 1resu) can see this trace
    Assertions.assertThat(repository.findAllForUser("user1")).hasSize(1);
    Assertions.assertThat(repository.findAllForUser("user2")).isEmpty();
  }

  @Test
  @DisplayName("Should extract username from files path")
  void shouldExtractUsernameFromFilesPath() {
    WebWolfTraceRepository repository = new WebWolfTraceRepository();

    // Add trace with username in path
    HttpExchange exchange = mock();
    HttpExchange.Request request = mock();
    when(exchange.getRequest()).thenReturn(request);
    when(exchange.getPrincipal()).thenReturn(null);
    when(request.getUri())
        .thenReturn(URI.create("http://localhost:9090/files/user1/document.pdf"));
    repository.add(exchange);

    // Verify user1 can see this trace
    Assertions.assertThat(repository.findAllForUser("user1")).hasSize(1);
    Assertions.assertThat(repository.findAllForUser("user2")).isEmpty();
  }
}
