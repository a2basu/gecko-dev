/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

"use strict";

var EXPORTED_SYMBOLS = ["WebDriverBiDi"];

const { XPCOMUtils } = ChromeUtils.import(
  "resource://gre/modules/XPCOMUtils.jsm"
);

XPCOMUtils.defineLazyModuleGetters(this, {
  Services: "resource://gre/modules/Services.jsm",

  error: "chrome://remote/content/shared/webdriver/Errors.jsm",
  Log: "chrome://remote/content/shared/Log.jsm",
  WebDriverSession: "chrome://remote/content/shared/webdriver/Session.jsm",
});

XPCOMUtils.defineLazyGetter(this, "logger", () =>
  Log.get(Log.TYPES.WEBDRIVER_BIDI)
);

/**
 * Entry class for the WebDriver BiDi support.
 *
 * @see https://w3c.github.io/webdriver-bidi
 */
class WebDriverBiDi {
  /**
   * Creates a new instance of the WebDriverBiDi class.
   *
   * @param {RemoteAgent} agent
   *     Reference to the Remote Agent instance.
   */
  constructor(agent) {
    this.agent = agent;
    this._running = false;

    this._session = null;
  }

  get address() {
    return `ws://${this.agent.host}:${this.agent.port}`;
  }

  get session() {
    return this._session;
  }

  /**
   * Create a new WebDriver session.
   *
   * @param {Object.<string, *>=} capabilities
   *     JSON Object containing any of the recognised capabilities as listed
   *     on the `WebDriverSession` class.
   *
   * @return {Object<String, Capabilities>}
   *     Object containing the current session ID, and all its capabilities.
   *
   * @throws {SessionNotCreatedError}
   *     If, for whatever reason, a session could not be created.
   */
  createSession(capabilities) {
    if (this.session) {
      throw new error.SessionNotCreatedError(
        "Maximum number of active sessions"
      );
    }

    this._session = new WebDriverSession(capabilities);

    // When the Remote Agent is listening, and a BiDi WebSocket connection
    // has been requested, register a path handler for the session.
    let webSocketUrl = null;
    if (this.agent.listening && this.session.capabilities.get("webSocketUrl")) {
      this.agent.server.registerPathHandler(this.session.path, this.session);
      webSocketUrl = `${this.address}${this.session.path}`;

      logger.debug(`Registered session handler: ${this.session.path}`);
    }

    // Also update the webSocketUrl capability to contain the session URL if
    // a path handler has been registered. Otherwise set its value to null.
    this.session.capabilities.set("webSocketUrl", webSocketUrl);

    return {
      sessionId: this.session.id,
      capabilities: this.session.capabilities,
    };
  }

  /**
   * Delete the current WebDriver session.
   */
  deleteSession() {
    if (!this.session) {
      return;
    }

    // When the Remote Agent is listening, and a BiDi WebSocket is active,
    // unregister the path handler for the session.
    if (this.agent.listening && this.session.capabilities.get("webSocketUrl")) {
      this.agent.server.registerPathHandler(this.session.path, null);
      logger.debug(`Unregistered session handler: ${this.session.path}`);
    }

    this.session.destroy();
    this._session = null;
  }

  /**
   * Starts the WebDriver BiDi support.
   */
  start() {
    if (this._running) {
      return;
    }

    this._running = true;

    Services.obs.notifyObservers(
      null,
      "remote-listening",
      `WebDriver BiDi listening on ${this.address}`
    );
  }

  /**
   * Stops the WebDriver BiDi support.
   */
  stop() {
    if (!this._running) {
      return;
    }

    try {
      this.deleteSession();
    } finally {
      this._running = false;
    }
  }
}
