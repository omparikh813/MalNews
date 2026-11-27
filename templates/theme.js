try {
  var saved = localStorage.getItem("malnews-theme");
  if (saved === "dark" || saved === "light") document.documentElement.dataset.theme = saved;
} catch (e) {}
