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

  // Filtering and pagination are separate concerns that both decide whether
  // a row is on screen, so they must not share one class -- paginating would
  // otherwise silently un-hide rows the filter had excluded. Filtering owns
  // `.hidden`; pagination owns `.page-hidden`; a row is visible only if
  // neither applies. Anything that re-filters notifies pagination through
  // this list so the page window is recomputed against the new result set.
  var afterFilter = [];
  function onFiltered(fn) {
    afterFilter.push(fn);
  }
  function notifyFiltered() {
    afterFilter.forEach(function (fn) {
      fn();
    });
  }

  // Set by enhanceAlsoFoundTable. A deep link can target a row sitting on
  // some other page of the table, so the anchor handler asks pagination to
  // turn to the page that actually contains it rather than un-hiding one
  // row behind the pager's back (which would leave the "Showing 1-25 of N"
  // status lying about what's on screen).
  var showRowsPageContaining = null;

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
    // Names the group for screen readers, so a pill is announced as
    // "Signal: exposed_service, toggle button" rather than a bare word with
    // no indication of what it filters.
    var legendId = "filter-group-" + label.toLowerCase().replace(/\W+/g, "-");
    legend.id = legendId;
    wrap.setAttribute("role", "group");
    wrap.setAttribute("aria-labelledby", legendId);
    wrap.appendChild(legend);

    var handlers = [];
    var buttons = values.map(function (value) {
      var btn = document.createElement("button");
      btn.type = "button";
      btn.className = "filter-pill";
      btn.textContent = value;
      btn.dataset.value = value;
      // These are toggles, not actions: without aria-pressed a screen
      // reader gives no way to tell an applied filter from an unapplied one,
      // since the only other cue is the background colour.
      btn.setAttribute("aria-pressed", "false");
      btn.addEventListener("click", function () {
        var on = btn.classList.toggle("active");
        btn.setAttribute("aria-pressed", on ? "true" : "false");
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
          btn.setAttribute("aria-pressed", "false");
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
    bar.setAttribute("role", "search");
    bar.setAttribute("aria-label", "Filter findings");

    var search = document.createElement("input");
    search.type = "search";
    search.className = "filter-search";
    search.placeholder = "Search findings…";
    search.setAttribute("aria-label", "Search findings");
    bar.appendChild(search);

    var typeGroup = buildToggleGroup("Type", collectFacetValues(items, "type"));
    var toolGroup = buildToggleGroup("Tool", collectFacetValues(items, "tools"));
    // `data-signals` has been emitted on every finding since the facet
    // attributes were added, but nothing ever read it -- the deterministic
    // scoring rubric is the project's whole differentiator, so being able to
    // ask "show me everything that fired sensitive_hostname_pattern" is
    // arguably the most useful filter of the three.
    var signalGroup = buildToggleGroup("Signal", collectFacetValues(items, "signals"));
    // Triage state is applied as data-triage by addTriageControls (which
    // runs first), so it costs nothing extra to facet on -- and "show me
    // only what I flagged" is most of the point of triaging at all.
    var triageGroup = buildToggleGroup("Triage", collectFacetValues(items, "triage"));
    bar.appendChild(typeGroup.el);
    bar.appendChild(toolGroup.el);
    bar.appendChild(signalGroup.el);
    bar.appendChild(triageGroup.el);

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
      var activeSignals = signalGroup.selected();
      var activeTriage = triageGroup.selected();
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
        if (visible && activeSignals.length) {
          var elSignals = (el.dataset.signals || "").split(/\s+/);
          var signalMatch = activeSignals.some(function (signal) {
            return elSignals.indexOf(signal) !== -1;
          });
          if (!signalMatch) {
            visible = false;
          }
        }
        if (visible && activeTriage.length
            && activeTriage.indexOf(el.dataset.triage || "") === -1) {
          visible = false;
        }
        if (visible && activeOnly && (el.dataset.methods || "").indexOf("active") === -1) {
          visible = false;
        }
        el.classList.toggle("hidden", !visible);
      });
      notifyFiltered();
    }

    search.addEventListener("input", applyFilters);
    typeGroup.onChange(applyFilters);
    toolGroup.onChange(applyFilters);
    signalGroup.onChange(applyFilters);
    triageGroup.onChange(applyFilters);
    activeOnlyBox.addEventListener("change", applyFilters);
    clearBtn.addEventListener("click", function () {
      search.value = "";
      typeGroup.clear();
      toolGroup.clear();
      signalGroup.clear();
      triageGroup.clear();
      activeOnlyBox.checked = false;
      applyFilters();
    });
  }

  /* Deep-linkable findings. The entity id (ADR-0001's own deterministic
     scheme) is already on every card as `data-entity-id`, so the anchor
     is stable across re-renders of the same scan -- a positional
     "#finding-3" would silently point at a different host the moment
     scoring reordered anything. Added here rather than in render_html()
     so the standalone file stays exactly as ADR-0010 D3 specifies. */
  function addAnchors() {
    all(".card").forEach(function (card) {
      var id = card.getAttribute("data-entity-id");
      if (!id || card.querySelector(".anchor-link")) {
        return;
      }
      var slug = "f-" + id.replace(/[^A-Za-z0-9_-]/g, "-");
      card.id = slug;
      var link = document.createElement("a");
      link.className = "anchor-link";
      link.href = "#" + slug;
      link.textContent = "#";
      link.title = "Link to this finding";
      link.setAttribute("aria-label", "Permanent link to this finding");
      var headline = card.querySelector(".headline");
      if (headline) {
        headline.appendChild(link);
      }
    });

    // "Also found" rows need anchors too. Without this, only the top N
    // findings were addressable and every inbound link to anything else --
    // including the relationship view's "in brief" links, which are built
    // from the whole graph, not just the top slice -- silently scrolled
    // nowhere. Found exactly that way: a link to a rank-6 wildcard
    // subdomain resolved to no element at all.
    all("table.also-found tbody tr[data-entity-id]").forEach(function (row) {
      var id = row.getAttribute("data-entity-id");
      if (!id) {
        return;
      }
      row.id = "f-" + id.replace(/[^A-Za-z0-9_-]/g, "-");
    });
    highlightHashTarget();
    // Clicking an anchor on the page changes the hash *without* reloading, so
    // the load-time pass alone would leave the highlight stuck on whichever
    // finding was linked first. Both entry points share one handler.
    window.addEventListener("hashchange", highlightHashTarget);
  }

  function highlightHashTarget() {
    all(".anchor-target").forEach(function (el) {
      el.classList.remove("anchor-target");
    });
    if (!window.location.hash) {
      return;
    }
    var target;
    try {
      target = document.querySelector(window.location.hash);
    } catch (err) {
      return; // a hand-edited, syntactically invalid fragment
    }
    if (!target) {
      return;
    }
    // A finding hidden by an active filter cannot be scrolled to; reveal it
    // rather than silently scrolling nowhere.
    target.classList.remove("hidden");
    // If it's a table row, it may also be on a page the pager isn't showing.
    if (target.tagName === "TR" && showRowsPageContaining) {
      showRowsPageContaining(target);
      target.classList.remove("page-hidden");
    }
    target.classList.add("anchor-target");
    target.scrollIntoView({ block: "center" });
  }

  /* --- "Also found": sortable + paginated ----------------------------
     This is the noisy tail -- a real target produced 529 findings -- and a
     flat dump of it recreates the exact unprioritised-pile problem Glean
     exists to solve, just lower down the page. Sorting and paging are added
     here rather than in render_html() so the standalone file keeps its
     complete, un-paginated list (ADR-0010 D3: it must stay readable with no
     JS at all, and a paginated table with a dead pager would be worse than
     a long one). */
  var PAGE_SIZE = 25;

  function cellText(row, index) {
    var cell = row.children[index];
    return cell ? cell.textContent.trim() : "";
  }

  function enhanceAlsoFoundTable() {
    var table = document.querySelector("table.also-found");
    if (!table) {
      return;
    }
    var tbody = table.tBodies[0];
    if (!tbody || !tbody.rows.length) {
      return;
    }
    var headers = all("thead th", table);
    var state = { index: null, ascending: true };
    var page = 1;

    function visibleRows() {
      return all("tr", tbody).filter(function (row) {
        return !row.classList.contains("hidden");
      });
    }

    function applyPaging() {
      var rows = visibleRows();
      var pages = Math.max(1, Math.ceil(rows.length / PAGE_SIZE));
      if (page > pages) {
        page = pages;
      }
      var start = (page - 1) * PAGE_SIZE;
      all("tr", tbody).forEach(function (row) {
        row.classList.add("page-hidden");
      });
      rows.slice(start, start + PAGE_SIZE).forEach(function (row) {
        row.classList.remove("page-hidden");
      });
      status.textContent = rows.length
        ? "Showing " + (start + 1) + "–" + Math.min(start + PAGE_SIZE, rows.length) +
          " of " + rows.length
        : "No findings match the current filters.";
      prev.disabled = page <= 1;
      next.disabled = page >= pages;
      pager.hidden = rows.length <= PAGE_SIZE && page === 1;
    }

    function sortBy(index) {
      // Third click on the same column clears the sort and restores the
      // renderer's own priority order, which is the meaningful default here
      // -- there'd otherwise be no way back to it without a reload.
      if (state.index === index && !state.ascending) {
        state.index = null;
      } else {
        state.ascending = state.index === index ? !state.ascending : true;
        state.index = index;
      }
      var rows = all("tr", tbody);
      if (state.index === null) {
        rows.sort(function (a, b) {
          return (+a.dataset.originalOrder) - (+b.dataset.originalOrder);
        });
      } else {
        var numeric = rows.every(function (row) {
          var text = cellText(row, index);
          return text === "" || !isNaN(parseFloat(text));
        });
        rows.sort(function (a, b) {
          var x = cellText(a, index);
          var y = cellText(b, index);
          var result = numeric
            ? (parseFloat(x) || 0) - (parseFloat(y) || 0)
            : x.localeCompare(y, undefined, { numeric: true, sensitivity: "base" });
          return state.ascending ? result : -result;
        });
      }
      rows.forEach(function (row) {
        tbody.appendChild(row);
      });
      headers.forEach(function (th, i) {
        th.setAttribute(
          "aria-sort",
          state.index === i ? (state.ascending ? "ascending" : "descending") : "none"
        );
        th.classList.toggle("sorted", state.index === i);
        th.classList.toggle("sorted-desc", state.index === i && !state.ascending);
      });
      page = 1;
      applyPaging();
    }

    all("tr", tbody).forEach(function (row, i) {
      row.dataset.originalOrder = String(i);
    });

    headers.forEach(function (th, index) {
      th.setAttribute("aria-sort", "none");
      var button = document.createElement("button");
      button.type = "button";
      button.className = "sort-btn";
      button.innerHTML = th.innerHTML;
      button.setAttribute("aria-label", "Sort by " + th.textContent.trim());
      button.addEventListener("click", function () {
        sortBy(index);
      });
      th.textContent = "";
      th.appendChild(button);
    });

    var pager = document.createElement("div");
    pager.className = "pager";
    var prev = document.createElement("button");
    prev.type = "button";
    prev.className = "pager-btn";
    prev.textContent = "Previous";
    var next = document.createElement("button");
    next.type = "button";
    next.className = "pager-btn";
    next.textContent = "Next";
    var status = document.createElement("span");
    status.className = "pager-status";
    status.setAttribute("role", "status");
    status.setAttribute("aria-live", "polite");
    prev.addEventListener("click", function () {
      page -= 1;
      applyPaging();
    });
    next.addEventListener("click", function () {
      page += 1;
      applyPaging();
    });
    pager.appendChild(prev);
    pager.appendChild(status);
    pager.appendChild(next);
    table.parentNode.insertBefore(pager, table.nextSibling);

    onFiltered(function () {
      page = 1;
      applyPaging();
    });

    showRowsPageContaining = function (row) {
      var index = visibleRows().indexOf(row);
      if (index === -1) {
        // Filtered out entirely -- no page contains it. Report that rather
        // than pretending, so the caller can clear filters instead.
        return false;
      }
      page = Math.floor(index / PAGE_SIZE) + 1;
      applyPaging();
      return true;
    };

    applyPaging();
  }

  /* --- Per-finding triage --------------------------------------------
     Turns a report into a workflow: mark a finding reviewed, flagged, or a
     false positive and have that survive a reload. Keyed by ADR-0001's
     entity id, the same stable key the diff and the anchors use, so a
     decision made today still attaches to the same real-world thing after a
     re-scan reorders everything.

     State is applied as a `data-triage` attribute on the finding's own
     element, which makes it available to the filter bar for free -- the
     facet machinery already reads data-* attributes. */
  var TRIAGE_STATES = ["reviewed", "flagged", "false_positive"];
  var TRIAGE_LABELS = {
    reviewed: "Reviewed",
    flagged: "Flagged",
    false_positive: "False positive",
  };

  function loadTriage() {
    var node = document.getElementById("triage-state");
    if (!node) {
      return {};
    }
    try {
      return JSON.parse(node.textContent) || {};
    } catch (err) {
      return {};
    }
  }

  function addTriageControls() {
    if (!scanId) {
      return;
    }
    var saved = loadTriage();
    all("[data-entity-id]").forEach(function (el) {
      var id = el.getAttribute("data-entity-id");
      if (!id || el.querySelector(".triage")) {
        return;
      }
      if (saved[id]) {
        el.setAttribute("data-triage", saved[id]);
      }

      var wrap = document.createElement("span");
      wrap.className = "triage";
      wrap.setAttribute("role", "group");
      wrap.setAttribute("aria-label", "Triage this finding");

      var buttons = TRIAGE_STATES.map(function (state) {
        var btn = document.createElement("button");
        btn.type = "button";
        btn.className = "triage-btn triage-" + state;
        btn.dataset.state = state;
        btn.textContent = TRIAGE_LABELS[state];
        btn.setAttribute("aria-pressed", saved[id] === state ? "true" : "false");
        wrap.appendChild(btn);
        return btn;
      });

      function render(state) {
        if (state) {
          el.setAttribute("data-triage", state);
        } else {
          el.removeAttribute("data-triage");
        }
        buttons.forEach(function (b) {
          b.setAttribute("aria-pressed", b.dataset.state === state ? "true" : "false");
        });
      }

      buttons.forEach(function (btn) {
        btn.addEventListener("click", function () {
          // Clicking the active state clears it: untriaged is the absence
          // of a decision, not a fourth button.
          var next = el.getAttribute("data-triage") === btn.dataset.state ? "" : btn.dataset.state;
          var previous = el.getAttribute("data-triage") || "";
          render(next);
          var body = new URLSearchParams();
          body.set("entity_id", id);
          body.set("state", next);
          fetch("/scan/" + encodeURIComponent(scanId) + "/triage", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: body.toString(),
          })
            .then(function (response) {
              if (!response.ok) {
                throw new Error("triage rejected: " + response.status);
              }
            })
            .catch(function () {
              // Roll the optimistic update back rather than leaving the
              // page claiming a decision the server never stored.
              render(previous);
              wrap.classList.add("triage-failed");
              setTimeout(function () {
                wrap.classList.remove("triage-failed");
              }, 2000);
            });
        });
      });

      if (el.tagName === "TR") {
        // Its own cell, not crammed into the "Seen by" column. Appended at
        // the end so every existing column index stays valid for the sort
        // handler, which addresses cells positionally.
        var cell = document.createElement("td");
        cell.className = "triage-cell";
        cell.appendChild(wrap);
        el.appendChild(cell);
      } else {
        var host = el.querySelector(".seen-by") || el;
        host.appendChild(wrap);
      }
    });

    // One matching header cell, or the table's column count no longer
    // matches its rows and the browser's own accessibility mapping breaks.
    var head = document.querySelector("table.also-found thead tr");
    if (head && document.querySelector("td.triage-cell") && !head.querySelector(".triage-th")) {
      var th = document.createElement("th");
      th.className = "triage-th";
      th.textContent = "Triage";
      head.appendChild(th);
    }
  }

  addCopyButtons();
  linkProvenance();
  addTriageControls();
  buildFilterBar();
  enhanceAlsoFoundTable();
  addAnchors();
})();
