/*
 * SPDX-FileCopyrightText: Copyright © 2017 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.webwolf.requests;

import static org.owasp.webgoat.webwolf.requests.WebWolfTraceRepository.Exclusion.contains;
import static org.owasp.webgoat.webwolf.requests.WebWolfTraceRepository.Exclusion.endsWith;

import com.google.common.collect.EvictingQueue;
import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.actuate.web.exchanges.HttpExchange;
import org.springframework.boot.actuate.web.exchanges.HttpExchangeRepository;

/**
 * Keep track of all the incoming requests, we are only keeping track of request originating from
 * WebGoat.
 */
public class WebWolfTraceRepository implements HttpExchangeRepository {
  private enum MatchingMode {
    CONTAINS,
    ENDS_WITH,
    EQUALS;
  }

  record Exclusion(String path, MatchingMode mode) {
    public boolean matches(String path) {
      return switch (mode) {
        case CONTAINS -> path.contains(this.path);
        case ENDS_WITH -> path.endsWith(this.path);
        case EQUALS -> path.equals(this.path);
      };
    }

    public static Exclusion contains(String exclusionPattern) {
      return new Exclusion(exclusionPattern, MatchingMode.CONTAINS);
    }

    public static Exclusion endsWith(String exclusionPattern) {
      return new Exclusion(exclusionPattern, MatchingMode.ENDS_WITH);
    }
  }

  /**
   * Wrapper class to associate an HttpExchange with the user who triggered it.
   * This enables per-user isolation of recorded exchanges.
   */
  record UserHttpExchange(HttpExchange exchange, String username) {}

  private final EvictingQueue<UserHttpExchange> traces = EvictingQueue.create(10000);
  private final List<Exclusion> exclusionList =
      List.of(
          contains("/tmpdir"),
          contains("/home"),
          endsWith("/files"),
          contains("/images/"),
          contains("/js/"),
          contains("/webjars/"),
          contains("/requests"),
          contains("/css/"),
          contains("/mail"));

  @Override
  public List<HttpExchange> findAll() {
    return traces.stream().map(UserHttpExchange::exchange).toList();
  }

  /**
   * Returns all exchanges for a specific user.
   *
   * @param username the username to filter by
   * @return list of HttpExchange objects belonging to the specified user
   */
  public List<HttpExchange> findAllForUser(String username) {
    if (username == null) {
      return List.of();
    }
    return traces.stream()
        .filter(t -> username.equals(t.username()))
        .map(UserHttpExchange::exchange)
        .toList();
  }

  private boolean isInExclusionList(String path) {
    return exclusionList.stream().anyMatch(e -> e.matches(path));
  }

  @Override
  public void add(HttpExchange httpTrace) {
    var path = httpTrace.getRequest().getUri().getPath();
    if (!isInExclusionList(path)) {
      // Extract username from the principal if available, otherwise derive from the request
      String username = extractUsername(httpTrace);
      traces.add(new UserHttpExchange(httpTrace, username));
    }
  }

  /**
   * Extracts the username from the HttpExchange. For unauthenticated requests (like /landing
   * callbacks), the username is derived from the request path or query parameters.
   *
   * @param httpTrace the HTTP exchange
   * @return the username associated with this exchange
   */
  private String extractUsername(HttpExchange httpTrace) {
    // First, try to get the authenticated principal
    var principal = httpTrace.getPrincipal();
    if (principal != null && principal.getName() != null) {
      return principal.getName();
    }

    // For unauthenticated requests, extract username from the request
    var uri = httpTrace.getRequest().getUri();
    var path = uri.getPath();
    var query = uri.getQuery();

    // Extract username from /files/{username}/ paths
    if (path != null && path.contains("/files/")) {
      String[] parts = path.split("/files/");
      if (parts.length > 1) {
        String[] userParts = parts[1].split("/");
        if (userParts.length > 0 && !userParts[0].isEmpty()) {
          return userParts[0];
        }
      }
    }

    // Extract username from /landing?uniqueCode=... (uniqueCode is reversed username)
    if (path != null && path.contains("/landing") && query != null && query.contains("uniqueCode=")) {
      String[] params = query.split("&");
      for (String param : params) {
        if (param.startsWith("uniqueCode=")) {
          String uniqueCode = param.substring("uniqueCode=".length());
          // uniqueCode is the reversed username
          return new StringBuilder(uniqueCode).reverse().toString();
        }
      }
    }

    // For other unauthenticated requests (e.g., /landing?text=...), we cannot determine the user
    // Return null to indicate no user association
    return null;
  }
}
