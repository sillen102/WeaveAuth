// Counts down every `[data-countdown]` element (seconds to wait). Without
// this script the page shows the starting number, which stays correct text.
document.querySelectorAll("[data-countdown]").forEach(function (el) {
  var end = Date.now() + Number(el.dataset.countdown) * 1000;
  var wait = el.querySelector(".countdown-wait");
  var ready = el.querySelector(".countdown-ready");
  var number = el.querySelector(".countdown-number");
  var unit = el.querySelector(".countdown-unit");

  function tick() {
    var left = Math.ceil((end - Date.now()) / 1000);
    if (left <= 0) {
      clearInterval(timer);
      wait.hidden = true;
      ready.hidden = false;
      return;
    }
    number.textContent = left;
    unit.textContent = left === 1 ? "second" : "seconds";
  }

  var timer = setInterval(tick, 250);
  tick();
});
