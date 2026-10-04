// The reset link carries its token in the fragment, which never reaches a
// server or a Referer. It is kept in this tab's sessionStorage, so a reload or
// a rejected password (whose redirect carries no token) doesn't lose it, and
// taken out of the address bar.
var KEY = "wa_reset_token";
var match = /(?:^#|&)token=([A-Za-z0-9_-]+)/.exec(location.hash);
var token = match ? match[1] : null;
try {
  if (token) {
    sessionStorage.setItem(KEY, token);
  } else {
    token = sessionStorage.getItem(KEY);
  }
} catch (e) {
  // Storage blocked: the token still works for this page load.
}
if (token) {
  document.getElementById("token").value = token;
  document.getElementById("reset-form").hidden = false;
} else {
  // One message at a time: without a token there's nothing to retry here.
  ["reset-intro", "reset-weak-password"].forEach(function (id) {
    var el = document.getElementById(id);
    if (el) {
      el.hidden = true;
    }
  });
  document.getElementById("reset-no-token").hidden = false;
}
if (match) {
  history.replaceState(null, "", location.pathname + location.search);
}
