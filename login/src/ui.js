// Binds the passkey/WebAuthn triggers Kratos puts on its nodes. The rendered page carries them as
// data-wa-trigger / data-wa-onload (never as inline handlers, which the CSP forbids); the
// functions they name come from the script node Kratos serves with the flow.
(function () {
  "use strict";
  var KNOWN = [
    "oryWebAuthnRegistration",
    "oryWebAuthnLogin",
    "oryPasskeyLogin",
    "oryPasskeyLoginAutocompleteInit",
    "oryPasskeyRegistration",
    "oryPasskeySettingsRegistration"
  ];

  function call(name) {
    if (KNOWN.indexOf(name) === -1 || typeof window[name] !== "function") {
      return;
    }
    window[name]();
  }

  function bind() {
    document.querySelectorAll("[data-wa-trigger]").forEach(function (el) {
      el.addEventListener("click", function (event) {
        event.preventDefault();
        call(el.getAttribute("data-wa-trigger"));
      });
    });
    document.querySelectorAll("[data-wa-onload]").forEach(function (el) {
      var name = el.getAttribute("data-wa-onload");
      if (window.__oryWebAuthnInitialized) {
        call(name);
      } else {
        window.addEventListener("oryWebAuthnInitialized", function () { call(name); }, { once: true });
      }
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", bind);
  } else {
    bind();
  }
})();
