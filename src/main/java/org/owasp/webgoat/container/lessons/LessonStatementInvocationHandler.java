/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.lessons;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.regex.Pattern;

/**
 * Handler which validates SQL statements to prevent cross-schema access through qualified
 * identifiers. This prevents users from accessing other users' lesson schemas or the CONTAINER
 * schema by using qualified table names like "OTHER_USER".table_name.
 */
public class LessonStatementInvocationHandler implements InvocationHandler {

  private final Statement targetStatement;
  private final String currentUsername;

  // Pattern to detect schema-qualified identifiers: "schema_name".table or schema.table
  // This matches quoted identifiers followed by a dot and another identifier
  private static final Pattern QUALIFIED_IDENTIFIER_PATTERN =
      Pattern.compile(
          "\"[^\"]+\"\\s*\\.\\s*[a-zA-Z_][a-zA-Z0-9_]*|[a-zA-Z_][a-zA-Z0-9_]*\\s*\\.\\s*[a-zA-Z_][a-zA-Z0-9_]*",
          Pattern.CASE_INSENSITIVE);

  // Pattern to detect references to CONTAINER schema (the main security concern)
  private static final Pattern CONTAINER_SCHEMA_PATTERN =
      Pattern.compile("\"?CONTAINER\"?\\s*\\.", Pattern.CASE_INSENSITIVE);

  public LessonStatementInvocationHandler(Statement targetStatement, String currentUsername) {
    this.targetStatement = targetStatement;
    this.currentUsername = currentUsername;
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    String methodName = method.getName();

    // Intercept SQL execution methods to validate the SQL
    if (methodName.equals("execute")
        || methodName.equals("executeQuery")
        || methodName.equals("executeUpdate")
        || methodName.equals("executeLargeUpdate")) {
      if (args != null && args.length > 0 && args[0] instanceof String) {
        String sql = (String) args[0];
        validateSql(sql);
      }
    } else if (methodName.equals("addBatch") && args != null && args.length > 0) {
      if (args[0] instanceof String) {
        String sql = (String) args[0];
        validateSql(sql);
      }
    }

    try {
      return method.invoke(targetStatement, args);
    } catch (InvocationTargetException e) {
      throw e.getTargetException();
    }
  }

  /**
   * Validates SQL to prevent cross-schema access through qualified identifiers.
   *
   * @param sql The SQL statement to validate
   * @throws SQLException if the SQL contains disallowed schema-qualified identifiers
   */
  private void validateSql(String sql) throws SQLException {
    validateSqlStatic(sql, currentUsername);
  }

  /**
   * Static method to validate SQL to prevent cross-schema access through qualified identifiers.
   * This method can be called from other classes.
   *
   * @param sql The SQL statement to validate
   * @param currentUsername The current user's username
   * @throws SQLException if the SQL contains disallowed schema-qualified identifiers
   */
  public static void validateSqlStatic(String sql, String currentUsername) throws SQLException {
    if (sql == null || sql.trim().isEmpty()) {
      return;
    }

    // Remove string literals to avoid false positives from quoted strings in SQL
    String sqlWithoutLiterals = removeStringLiteralsStatic(sql);

    // Check for CONTAINER schema references (critical security issue)
    if (CONTAINER_SCHEMA_PATTERN.matcher(sqlWithoutLiterals).find()) {
      throw new SQLException(
          "Access denied: Access to CONTAINER schema is not allowed in lesson connections");
    }

    // Check for any schema-qualified identifiers (excluding INFORMATION_SCHEMA which is allowed)
    var matcher = QUALIFIED_IDENTIFIER_PATTERN.matcher(sqlWithoutLiterals);
    while (matcher.find()) {
      String qualifiedId = matcher.group();
      // Extract the schema part (before the dot)
      String schemaPart = qualifiedId.split("\\.")[0].trim().replace("\"", "");

      // Skip INFORMATION_SCHEMA as it's needed for some lessons
      if (schemaPart.equalsIgnoreCase("INFORMATION_SCHEMA")) {
        continue;
      }

      // Allow references to the current user's schema only
      if (!schemaPart.equalsIgnoreCase(currentUsername)) {
        throw new SQLException(
            "Access denied: Cross-schema access is not allowed. You can only access tables in your"
                + " own schema.");
      }
    }
  }

  /**
   * Removes string literals from SQL to avoid false positives when detecting schema-qualified
   * identifiers. This handles both single-quoted strings and escaped quotes.
   *
   * @param sql The SQL statement
   * @return SQL with string literals replaced by empty strings
   */
  private String removeStringLiterals(String sql) {
    return removeStringLiteralsStatic(sql);
  }

  /**
   * Static method to remove string literals from SQL to avoid false positives when detecting
   * schema-qualified identifiers. This handles both single-quoted strings and escaped quotes.
   *
   * @param sql The SQL statement
   * @return SQL with string literals replaced by empty strings
   */
  private static String removeStringLiteralsStatic(String sql) {
    // Replace single-quoted strings (handling escaped quotes)
    return sql.replaceAll("'(?:[^']|'')*'", "''");
  }
}
