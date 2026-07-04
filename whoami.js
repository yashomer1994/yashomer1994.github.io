(function () {
  function run() {
    var term = document.getElementById("whoami-term");
    var out = document.getElementById("whoami-out");
    var hint = document.getElementById("whoami-hint");
    var caret = document.getElementById("whoami-cursor");
    if (!term || !out || term.classList.contains("is-done")) return;

    term.classList.add("is-done");
    if (hint) hint.hidden = true;
    out.hidden = false;
    if (caret) caret.hidden = false;
    term.setAttribute("aria-expanded", "true");
    term.removeAttribute("role");
    term.removeAttribute("tabindex");
  }

  document.addEventListener("DOMContentLoaded", function () {
    var term = document.getElementById("whoami-term");
    if (!term) return;

    term.setAttribute("aria-expanded", "false");
    term.addEventListener("click", run);
    term.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        run();
      }
    });
  });
})();
