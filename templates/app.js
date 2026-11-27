"use strict";

(function () {
  var $ = function (selector, root) { return (root || document).querySelector(selector); };
  var $$ = function (selector, root) { return Array.prototype.slice.call((root || document).querySelectorAll(selector)); };

  // Dark mode toggle
  var root = document.documentElement;
  var toggle = $("#theme-toggle");
  function currentTheme() {
    return root.dataset.theme || (window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  }
  if (toggle) {
    toggle.hidden = false;
    toggle.setAttribute("aria-pressed", String(currentTheme() === "dark"));
    toggle.addEventListener("click", function () {
      var next = currentTheme() === "dark" ? "light" : "dark";
      root.dataset.theme = next;
      try { localStorage.setItem("malnews-theme", next); } catch (e) {}
      toggle.setAttribute("aria-pressed", String(next === "dark"));
    });
  }

  // Headline filters: show or hide the cards that are already on the page
  var chipBar = $(".chips");
  var cards = $$(".card");
  var headlineStatus = $("#headline-status");
  function matches(card, filter) {
    if (filter === "all") return true;
    if (filter === "kev") return card.dataset.kev === "1";
    if (filter === "zero") return card.dataset.zero === "1";
    return card.dataset.band === filter;
  }
  if (chipBar) {
    chipBar.hidden = false;
    $$("[data-filter]", chipBar).forEach(function (chip) {
      chip.addEventListener("click", function () {
        var filter = chip.dataset.filter;
        $$("[data-filter]", chipBar).forEach(function (other) {
          other.setAttribute("aria-pressed", String(other === chip));
        });
        var shown = 0;
        cards.forEach(function (card) {
          var show = matches(card, filter);
          card.hidden = !show;
          if (show) shown += 1;
        });
        $$(".group").forEach(function (group) {
          group.hidden = $$(".card:not([hidden])", group).length === 0;
        });
        headlineStatus.textContent = shown + (shown === 1 ? " headline" : " headlines") +
          (filter === "all" ? "" : " match this filter");
      });
    });
  }

  // Archive search: hide or show the editions already listed on the page
  var box = $("#archive-search");
  var tools = $("#archive-tools");
  var status = $("#archive-status");
  var months = $$(".month");
  var rows = $$(".edition");
  var wasOpen = months.map(function (month) { return month.open; });
  var index = null;
  var loading = null;

  function loadIndex() {
    if (!loading) {
      loading = fetch("data/search.json")
        .then(function (response) { if (!response.ok) throw new Error(String(response.status)); return response.json(); })
        .then(function (data) { index = data; })
        .catch(function () { loading = null; status.textContent = "Search is unavailable right now. The list below still works."; });
    }
    return loading;
  }

  function search() {
    var query = box.value.trim().toLowerCase();
    if (!query) {
      rows.forEach(function (row) { row.hidden = false; });
      months.forEach(function (month, i) { month.hidden = false; month.open = wasOpen[i]; });
      status.textContent = "";
      return;
    }
    if (!index) { return; }
    var words = query.split(/\s+/);
    var found = 0;
    rows.forEach(function (row) {
      var text = (index[row.dataset.date] || "") + " " + row.textContent.toLowerCase();
      var ok = words.every(function (word) { return text.indexOf(word) !== -1; });
      row.hidden = !ok;
      if (ok) found += 1;
    });
    months.forEach(function (month) {
      var any = $$(".edition:not([hidden])", month).length > 0;
      month.hidden = !any;
      month.open = any;
    });
    status.textContent = found === 0
      ? "No editions match “" + box.value.trim() + "”. Try one word, or a CVE ID."
      : found + (found === 1 ? " edition matches" : " editions match") + " “" + box.value.trim() + "”.";
  }

  if (box && tools) {
    tools.hidden = false;
    var timer = null;
    box.addEventListener("input", function () {
      clearTimeout(timer);
      timer = setTimeout(function () { loadIndex().then(search); }, 150);
    });
    box.addEventListener("keydown", function (event) {
      if (event.key === "Escape") { box.value = ""; search(); }
    });
  }
})();
