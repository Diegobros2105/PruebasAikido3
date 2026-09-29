/*
 * SPDX-FileCopyrightText: Copyright © 2021 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.owasp.webgoat.container.lessons;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.Statement;
import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Handler which sets the correct schema for the currently bounded user and wraps Statement objects
 * to prevent cross-schema access. This way users are not seeing each other data, and we can reset
 * data for just one particular user. The handler intercepts statement creation methods and wraps
 * the returned statements with validation logic that prevents schema-qualified identifiers from
 * accessing other users' schemas.
 */
public class LessonConnectionInvocationHandler implements InvocationHandler {

  private final Connection targetConnection;

  public LessonConnectionInvocationHandler(Connection targetConnection) {
    this.targetConnection = targetConnection;
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    var authentication = SecurityContextHolder.getContext().getAuthentication();
    String username = null;
    if (authentication != null && authentication.getPrincipal() instanceof WebGoatUser user) {
      username = user.getUsername();
      try (var statement = targetConnection.createStatement()) {
        statement.execute("SET SCHEMA \"" + username + "\"");
      }
    }

    // Intercept statement creation methods to wrap the returned statements
    String methodName = method.getName();
    if (methodName.equals("createStatement")
        || methodName.equals("prepareStatement")
        || methodName.equals("prepareCall")) {
      // Validate SQL for prepareStatement and prepareCall (SQL is in first argument)
      if ((methodName.equals("prepareStatement") || methodName.equals("prepareCall"))
          && args != null
          && args.length > 0
          && args[0] instanceof String
          && username != null) {
        String sql = (String) args[0];
        LessonStatementInvocationHandler.validateSqlStatic(sql, username);
      }

      try {
        Object result = method.invoke(targetConnection, args);
        if (result instanceof Statement && username != null) {
          return wrapStatement((Statement) result, username);
        }
        return result;
      } catch (InvocationTargetException e) {
        throw e.getTargetException();
      }
    }

    try {
      return method.invoke(targetConnection, args);
    } catch (InvocationTargetException e) {
      throw e.getTargetException();
    }
  }

  /**
   * Wraps a Statement object with a proxy that validates SQL to prevent cross-schema access.
   *
   * @param statement The statement to wrap
   * @param username The current user's username
   * @return A proxied statement that validates SQL before execution
   */
  private Statement wrapStatement(Statement statement, String username) {
    // Determine which interfaces to proxy based on the actual statement type
    Class<?>[] interfaces;
    if (statement instanceof CallableStatement) {
      interfaces = new Class<?>[] {CallableStatement.class};
    } else if (statement instanceof PreparedStatement) {
      interfaces = new Class<?>[] {PreparedStatement.class};
    } else {
      interfaces = new Class<?>[] {Statement.class};
    }

    return (Statement)
        Proxy.newProxyInstance(
            statement.getClass().getClassLoader(),
            interfaces,
            new LessonStatementInvocationHandler(statement, username));
  }
}
