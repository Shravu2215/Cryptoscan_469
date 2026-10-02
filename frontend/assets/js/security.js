/**
 * CryptoScan Security Helpers  (P0-7 browser security)
 *
 * Load this script BEFORE any page script that renders API / scan data.
 * It exposes two globals:
 *
 *   escapeHtml(str)            – HTML-entity-encodes a string so it is safe
 *                                to splice into innerHTML template literals.
 *
 *   setTextSafe(el, str)       – Sets el.textContent, null-safe.
 *
 * RULE: Any field that originates from scanned-repo content (file path, rule
 * message, algorithm name, finding description, repo name, library name, etc.)
 * MUST be wrapped with escapeHtml() before being interpolated into an innerHTML
 * or insertAdjacentHTML call.  For single-value slots, prefer textContent.
 */

(function () {
  'use strict';

  /**
   * HTML-entity-encode a value so it is safe inside innerHTML.
   * Handles null / undefined / numbers / booleans by coercing to string first.
   *
   * @param  {*}      val
   * @returns {string} HTML-safe string
   */
  function escapeHtml(val) {
    if (val == null) return '';
    return String(val)
      .replace(/&/g,  '&amp;')
      .replace(/</g,  '&lt;')
      .replace(/>/g,  '&gt;')
      .replace(/"/g,  '&quot;')
      .replace(/'/g,  '&#39;');
  }

  /**
   * Null-safe textContent setter.
   * @param {HTMLElement|null} el
   * @param {*} val
   */
  function setTextSafe(el, val) {
    if (!el) return;
    el.textContent = (val == null) ? '' : String(val);
  }

  window.escapeHtml   = escapeHtml;
  window.setTextSafe  = setTextSafe;
})();
