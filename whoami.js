(function () {
  function openProfile() {
    var btn = document.getElementById("whoami-run");
    var profile = document.getElementById("whoami-profile");
    if (!btn || !profile || btn.getAttribute("aria-expanded") === "true") return;

    btn.setAttribute("aria-expanded", "true");
    profile.hidden = false;
  }

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("whoami-run");
    if (!btn) return;
    btn.addEventListener("click", openProfile);
  });
})();
