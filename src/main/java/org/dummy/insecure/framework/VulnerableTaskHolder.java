/*
 * SPDX-FileCopyrightText: Copyright © 2019 WebGoat authors
 * SPDX-License-Identifier: GPL-2.0-or-later
 */
package org.dummy.insecure.framework;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.time.LocalDateTime;
import lombok.extern.slf4j.Slf4j;

@Slf4j
// TODO move back to lesson
public class VulnerableTaskHolder implements Serializable {

  private static final long serialVersionUID = 2;

  private String taskName;
  private String taskAction;
  private LocalDateTime requestedExecutionTime;

  public VulnerableTaskHolder(String taskName, String taskAction) {
    super();
    this.taskName = taskName;
    this.taskAction = taskAction;
    this.requestedExecutionTime = LocalDateTime.now();
  }

  @Override
  public String toString() {
    return "VulnerableTaskHolder [taskName="
        + taskName
        + ", taskAction="
        + taskAction
        + ", requestedExecutionTime="
        + requestedExecutionTime
        + "]";
  }

  /**
   * Execute a task when de-serializing a saved or received object.
   */
  private void readObject(ObjectInputStream stream) throws Exception {
    // unserialize data so taskName and taskAction are available
    stream.defaultReadObject();

    // do something with the data
    log.info("restoring task: {}", taskName);
    log.info("restoring time: {}", requestedExecutionTime);

    if (requestedExecutionTime != null
        && (requestedExecutionTime.isBefore(LocalDateTime.now().minusMinutes(10))
            || requestedExecutionTime.isAfter(LocalDateTime.now()))) {
      // do nothing is the time is not within 10 minutes after the object has been created
      log.debug(this.toString());
      throw new IllegalArgumentException("outdated");
    }

    // condition is here to prevent you from destroying the goat altogether
    if ((taskAction.startsWith("sleep") || taskAction.startsWith("ping"))
        && taskAction.length() < 22) {
      
      // Validate command arguments to prevent resource exhaustion attacks
      if (!isValidTaskAction(taskAction)) {
        log.warn("Invalid task action rejected: {}", taskAction);
        throw new IllegalArgumentException("Invalid task action parameters");
      }
      
      log.info("about to execute: {}", taskAction);
      Process p = null;
      try {
        p = Runtime.getRuntime().exec(taskAction);
        final Process process = p;
        
        // Set a timeout to prevent indefinite blocking
        boolean completed = p.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);
        
        if (!completed) {
          log.warn("Process exceeded timeout, terminating: {}", taskAction);
          p.destroyForcibly();
          throw new IllegalArgumentException("Task execution timeout exceeded");
        }
        
        // Read output only if process completed within timeout
        BufferedReader in = new BufferedReader(new InputStreamReader(p.getInputStream()));
        String line = null;
        while ((line = in.readLine()) != null) {
          log.info(line);
        }
      } catch (IOException e) {
        log.error("IO Exception", e);
        if (p != null && p.isAlive()) {
          p.destroyForcibly();
        }
      } catch (InterruptedException e) {
        log.error("Process interrupted", e);
        if (p != null && p.isAlive()) {
          p.destroyForcibly();
        }
        Thread.currentThread().interrupt();
        throw new IllegalArgumentException("Task execution interrupted");
      } finally {
        // Ensure process is cleaned up
        if (p != null && p.isAlive()) {
          p.destroyForcibly();
        }
      }
    }
  }
  
  /**
   * Validates that the task action has reasonable parameters to prevent resource exhaustion.
   * For sleep commands, ensures duration is between 1 and 10 seconds.
   * For ping commands, ensures count is between 1 and 10.
   */
  private boolean isValidTaskAction(String action) {
    if (action == null || action.isEmpty()) {
      return false;
    }
    
    String[] parts = action.trim().split("\\s+");
    if (parts.length < 2) {
      return false;
    }
    
    String command = parts[0].toLowerCase();
    
    if ("sleep".equals(command)) {
      // Validate sleep duration (should be 1-10 seconds)
      try {
        int duration = Integer.parseInt(parts[1]);
        return duration >= 1 && duration <= 10;
      } catch (NumberFormatException e) {
        return false;
      }
    } else if ("ping".equals(command)) {
      // For ping, validate the count parameter
      // Windows: ping localhost -n <count>
      // Unix/Linux: ping -c <count> localhost or ping localhost (defaults to continuous, not allowed)
      
      // Check for count parameter in various positions
      for (int i = 1; i < parts.length; i++) {
        if (("-n".equals(parts[i]) || "-c".equals(parts[i])) && i + 1 < parts.length) {
          try {
            int count = Integer.parseInt(parts[i + 1]);
            return count >= 1 && count <= 10;
          } catch (NumberFormatException e) {
            return false;
          }
        }
      }
      // If no count parameter found, reject (would ping indefinitely)
      return false;
    }
    
    return false;
  }
}
