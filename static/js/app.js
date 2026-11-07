document.querySelectorAll(".theme-toggle").forEach(button => {
  const update = () => {
    const theme = document.documentElement.getAttribute("data-theme") || "light";
    button.textContent = theme === "dark" ? "☀" : "☾";
  };
  update();
  button.addEventListener("click", () => {
    const current = document.documentElement.getAttribute("data-theme") || "light";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("cyberguard-theme", next);
    document.querySelectorAll(".theme-toggle").forEach(b => b.textContent = next === "dark" ? "☀" : "☾");
  });
});
const menuButton = document.getElementById("mobileMenu");
const sidebar = document.getElementById("sidebar");
if (menuButton && sidebar) {
  const syncMenu = () => {
    const mobile = window.matchMedia("(max-width: 800px)").matches;
    if (mobile) {
      sidebar.classList.remove("open");
      document.body.classList.remove("sidebar-collapsed");
      menuButton.setAttribute("aria-expanded", "false");
    } else {
      document.body.classList.remove("sidebar-collapsed");
      menuButton.setAttribute("aria-expanded", "true");
    }
  };
  menuButton.addEventListener("click", () => {
    const mobile = window.matchMedia("(max-width: 800px)").matches;
    if (mobile) {
      const opened = sidebar.classList.toggle("open");
      menuButton.setAttribute("aria-expanded", String(opened));
    } else {
      const collapsed = document.body.classList.toggle("sidebar-collapsed");
      menuButton.setAttribute("aria-expanded", String(!collapsed));
    }
  });
  window.addEventListener("resize", syncMenu);
}

const FONT_STEPS = ["1.1", "1.3", "1.5"];
document.querySelectorAll(".font-toggle").forEach(button => {
  button.addEventListener("click", () => {
    const current = localStorage.getItem("cyberguard-fz") || "1.1";
    const next = FONT_STEPS[(FONT_STEPS.indexOf(current) + 1) % FONT_STEPS.length];
    localStorage.setItem("cyberguard-fz", next);
    document.documentElement.style.setProperty("--fz", next);
  });
});
