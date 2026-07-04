(function () {
  function toggleProfile() {
    var btn = document.getElementById("whoami-run");
    var profile = document.getElementById("whoami-profile");
    if (!btn || !profile) return;

    var open = btn.getAttribute("aria-expanded") === "true";
    if (open) {
      btn.setAttribute("aria-expanded", "false");
      profile.hidden = true;
    } else {
      btn.setAttribute("aria-expanded", "true");
      profile.hidden = false;
    }
  }

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("whoami-run");
    if (!btn) return;
    btn.addEventListener("click", toggleProfile);
  });
})();
