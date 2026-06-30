/* ==========================================================================
   site.js
   Progressive enhancement only: the page is fully usable without it.
   - Table-of-contents scrollspy (highlights the section in view)
   - Copy-to-clipboard buttons on code blocks
   - Mobile navigation toggle
   ========================================================================== */
(function () {
  "use strict";

  /* ----- Mobile nav --------------------------------------------------------- */
  var toggle = document.querySelector(".nav-toggle");
  var nav = document.querySelector(".site-nav");
  if (toggle && nav) {
    toggle.addEventListener("click", function () {
      var open = nav.classList.toggle("is-open");
      toggle.setAttribute("aria-expanded", open ? "true" : "false");
    });
    nav.addEventListener("click", function (e) {
      if (e.target.tagName === "A") {
        nav.classList.remove("is-open");
        toggle.setAttribute("aria-expanded", "false");
      }
    });
  }

  /* ----- Copy buttons ------------------------------------------------------- */
  var blocks = document.querySelectorAll(".codeblock");
  blocks.forEach(function (block) {
    var btn = block.querySelector(".codeblock__copy");
    var pre = block.querySelector("pre");
    if (!btn || !pre) return;
    btn.addEventListener("click", function () {
      var text = pre.innerText;
      var done = function () {
        var original = btn.getAttribute("data-label") || "Copy";
        btn.textContent = "Copied";
        btn.classList.add("is-done");
        window.setTimeout(function () {
          btn.textContent = original;
          btn.classList.remove("is-done");
        }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, done);
      } else {
        var ta = document.createElement("textarea");
        ta.value = text;
        document.body.appendChild(ta);
        ta.select();
        try { document.execCommand("copy"); } catch (e) { /* ignore */ }
        document.body.removeChild(ta);
        done();
      }
    });
  });

  /* ----- Scrollspy ---------------------------------------------------------- */
  var tocLinks = Array.prototype.slice.call(
    document.querySelectorAll(".toc a[href^='#']")
  );
  if (tocLinks.length && "IntersectionObserver" in window) {
    var map = {};
    var sections = [];
    tocLinks.forEach(function (link) {
      var id = link.getAttribute("href").slice(1);
      var section = document.getElementById(id);
      if (section) {
        map[id] = link;
        sections.push(section);
      }
    });

    var current = null;
    var setActive = function (id) {
      if (current === id) return;
      current = id;
      tocLinks.forEach(function (l) { l.classList.remove("is-active"); });
      if (map[id]) map[id].classList.add("is-active");
    };

    var observer = new IntersectionObserver(
      function (entries) {
        var visible = entries
          .filter(function (e) { return e.isIntersecting; })
          .sort(function (a, b) {
            return a.target.offsetTop - b.target.offsetTop;
          });
        if (visible.length) {
          setActive(visible[0].target.id);
        }
      },
      { rootMargin: "-20% 0px -70% 0px", threshold: 0 }
    );
    sections.forEach(function (s) { observer.observe(s); });
  }
})();
