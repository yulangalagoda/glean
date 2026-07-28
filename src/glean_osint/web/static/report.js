/* Interactive layer for the scan-result page (ADR-0011), injected only
   into the web response (app.py's _wrap_scan_result_for_web) -- never
   part of the self-contained brief.html/--out report.html file (ADR-0010
   D3 keeps that output zero-JS on purpose). Everything here operates on
   markup render_html() already emits (data-* facet attributes, span.src
   provenance markers) rather than requiring the shared renderer to know
   anything about the web app. Vendored locally, no CDN, matching
   ADR-0011's own "no external requests" discipline. */
(function () {
  "use strict";

  var scanId = document.body.getAttribute("data-scan-id") || "";

  function all(selector, root) {
    return Array.prototype.slice.call((root || document).querySelectorAll(selector));
  }

  function addCopyButtons() {
    all(".card .headline code, table.also-found td code").forEach(function (code) {
      if (code.parentElement.querySelector(".copy-btn")) {
        return;
      }
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "copy-btn";
      btn.textContent = "Copy";
      btn.setAttribute("aria-label", "Copy value to clipboard");
      btn.addEventListener("click", function (event) {
        event.preventDefault();
        var text = code.textContent;
        if (!navigator.clipboard) {
          return;
        }
        navigator.clipboard.writeText(text).then(function () {
          var original = btn.textContent;
          btn.textContent = "Copied";
          setTimeout(function () {
            btn.textContent = original;
          }, 1200);
        });
      });
      code.insertAdjacentElement("afterend", btn);
    });
  }

  function linkProvenance() {
    if (!scanId) {
      return;
    }
    all("span.src[data-tool]").forEach(function (span) {
      if (span.querySelector("a")) {
        return;
      }
      var tool = span.getAttribute("data-tool");
      var link = document.createElement("a");
      link.href = "/scan/" + encodeURIComponent(scanId) + "/raw/" + encodeURIComponent(tool);
      link.target = "_blank";
      link.rel = "noopener";
      link.textContent = span.textContent;
      span.textContent = "";
      span.appendChild(link);
    });
  }

  function collectFacetValues(items, attr) {
    var seen = {};
    items.forEach(function (el) {
      (el.dataset[attr] || "").split(/\s+/).filter(Boolean).forEach(function (value) {
        seen[value] = true;
      });
    });
    return Object.keys(seen).sort();
  }

  function buildToggleGroup(label, values) {
    var wrap = document.createElement("div");
    wrap.className = "filter-group";
    if (!values.length) {
      return { el: wrap, selected: function () { return []; }, onChange: function () {}, clear: function () {} };
    }
    var legend = document.createElement("span");
    legend.className = "filter-group-label";
    legend.textContent = label + ":";
    wrap.appendChild(legend);

    var handlers = [];
    var buttons = values.map(function (value) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "filter-pill";
      btn.textContent = value;
      btn.dataset.value = value;
      btn.addEventListener("click", function () {
        btn.classList.toggle("active");
        handlers.forEach(function (handler) {
          handler();
        });
      });
      wrap.appendChild(btn);
      return btn;
    });

    return {
      el: wrap,
      selected: function () {
        return buttons
          .filter(function (btn) {
            return btn.classList.contains("active");
          })
          .map(function (btn) {
            return btn.dataset.value;
          });
      },
      onChange: function (handler) {
        handlers.push(handler);
      },
      clear: function () {
        buttons.forEach(function (btn) {
          btn.classList.remove("active");
        });
      },
    };
  }

  function buildFilterBar() {
    var anchor = document.querySelector("h2");
    var cards = all(".card");
    var rows = all("table.also-found tbody tr");
    var items = cards.concat(rows);
    if (!anchor || !items.length) {
      return;
    }

    var bar = document.createElement("div");
    bar.className = "filter-bar";

    var search = document.createElement("input");
    search.type = "search";
    search.className = "filter-search";
    search.placeholder = "Search findings…";
    bar.appendChild(search);

    var typeGroup = buildToggleGroup("Type", collectFacetValues(items, "type"));
    var toolGroup = buildToggleGroup("Tool", collectFacetValues(items, "tools"));
    bar.appendChild(typeGroup.el);
    bar.appendChild(toolGroup.el);

    var activeOnlyLabel = document.createElement("label");
    activeOnlyLabel.className = "filter-active-only";
    var activeOnlyBox = document.createElement("input");
    activeOnlyBox.type = "checkbox";
    activeOnlyLabel.appendChild(activeOnlyBox);
    activeOnlyLabel.appendChild(document.createTextNode(" Active-collection findings only"));
    bar.appendChild(activeOnlyLabel);

    var clearBtn = document.createElement("button");
    clearBtn.type = "button";
    clearBtn.className = "filter-clear";
    clearBtn.textContent = "Clear filters";
    bar.appendChild(clearBtn);

    anchor.parentNode.insertBefore(bar, anchor);

    function applyFilters() {
      var query = search.value.trim().toLowerCase();
      var activeTypes = typeGroup.selected();
      var activeTools = toolGroup.selected();
      var activeOnly = activeOnlyBox.checked;

      items.forEach(function (el) {
        var visible = true;
        if (query && el.textContent.toLowerCase().indexOf(query) === -1) {
          visible = false;
        }
        if (visible && activeTypes.length && activeTypes.indexOf(el.dataset.type || "") === -1) {
          visible = false;
        }
        if (visible && activeTools.length) {
          var elTools = (el.dataset.tools || "").split(/\s+/);
          var matches = activeTools.some(function (tool) {
            return elTools.indexOf(tool) !== -1;
          });
          if (!matches) {
            visible = false;
          }
        }
        if (visible && activeOnly && (el.dataset.methods || "").indexOf("active") === -1) {
          visible = false;
        }
        el.classList.toggle("hidden", !visible);
      });
    }

    search.addEventListener("input", applyFilters);
    typeGroup.onChange(applyFilters);
    toolGroup.onChange(applyFilters);
    activeOnlyBox.addEventListener("change", applyFilters);
    clearBtn.addEventListener("click", function () {
      search.value = "";
      typeGroup.clear();
      toolGroup.clear();
      activeOnlyBox.checked = false;
      applyFilters();
    });
  }

  addCopyButtons();
  linkProvenance();
  buildFilterBar();
})();
