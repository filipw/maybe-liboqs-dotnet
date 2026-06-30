/* ==========================================================================
   highlight.js (local, dependency-free)
   A small syntax highlighter for the few languages used on this site:
   C#, XML/csproj, and shell. It wraps tokens in <span class="tok-*"> and the
   colours are defined in styles supplied below via the .codeblock theme.

   This is deliberately minimal. It is not a general-purpose parser; it only
   needs to colour the static snippets shown here. Highlighting runs after the
   raw text content of each <code> block, so the page is fully readable even
   if scripting is disabled.
   ========================================================================== */
(function () {
  "use strict";

  function escapeHtml(s) {
    return s
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;");
  }

  // Generic tokenizer driven by an ordered list of {type, re} rules.
  function tokenize(src, rules) {
    var out = "";
    var i = 0;
    outer: while (i < src.length) {
      for (var r = 0; r < rules.length; r++) {
        var rule = rules[r];
        rule.re.lastIndex = i;
        var m = rule.re.exec(src);
        if (m && m.index === i) {
          var text = m[0];
          if (rule.type) {
            out += '<span class="tok-' + rule.type + '">' + escapeHtml(text) + "</span>";
          } else {
            out += escapeHtml(text);
          }
          i += text.length;
          continue outer;
        }
      }
      out += escapeHtml(src[i]);
      i += 1;
    }
    return out;
  }

  var csharpKeywords =
    "abstract|as|base|bool|break|byte|case|catch|char|checked|class|const|continue|" +
    "decimal|default|delegate|do|double|else|enum|event|explicit|extern|false|finally|" +
    "fixed|float|for|foreach|goto|if|implicit|in|int|interface|internal|is|lock|long|" +
    "namespace|new|null|object|operator|out|override|params|private|protected|public|" +
    "readonly|ref|return|sbyte|sealed|short|sizeof|stackalloc|static|string|struct|" +
    "switch|this|throw|true|try|typeof|uint|ulong|unchecked|unsafe|ushort|using|var|" +
    "virtual|void|volatile|while|record|nameof|when|with|init|get|set|async|await";

  var csharpRules = [
    { type: "comment", re: /\/\/[^\n]*/y },
    { type: "comment", re: /\/\*[\s\S]*?\*\//y },
    { type: "string", re: /\$?@?"(?:[^"\\]|\\.|"")*"/y },
    { type: "string", re: /'(?:[^'\\]|\\.)'/y },
    { type: "number", re: /\b0[xX][0-9a-fA-F]+\b|\b\d+(?:\.\d+)?[fFdDmMlLuU]*\b/y },
    { type: "keyword", re: new RegExp("\\b(?:" + csharpKeywords + ")\\b", "y") },
    { type: "type", re: /\b[A-Z][A-Za-z0-9_]*\b/y },
    { type: "punct", re: /[{}()\[\].,;:?]/y },
    { type: "op", re: /=>|[-+*/%=<>!&|^~]+/y },
    { type: null, re: /\s+/y },
    { type: null, re: /[A-Za-z_][A-Za-z0-9_]*/y }
  ];

  var xmlRules = [
    { type: "comment", re: /<!--[\s\S]*?-->/y },
    { type: "tag", re: /<\/?[A-Za-z][\w.-]*/y },
    { type: "tag", re: /\/?>/y },
    { type: "attr", re: /[A-Za-z_:][\w.:-]*(?==)/y },
    { type: "string", re: /"[^"]*"|'[^']*'/y },
    { type: "op", re: /=/y },
    { type: null, re: /\s+/y }
  ];

  var shellRules = [
    { type: "comment", re: /#[^\n]*/y },
    { type: "string", re: /"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/y },
    {
      type: "keyword",
      re: /\b(?:dotnet|git|cd|chmod|sudo|apt|cmake|export|run|build|test|add|restore)\b/y
    },
    { type: "op", re: /[|&><]+/y },
    { type: null, re: /\s+/y }
  ];

  var grammars = {
    csharp: csharpRules,
    "language-csharp": csharpRules,
    xml: xmlRules,
    "language-xml": xmlRules,
    shell: shellRules,
    bash: shellRules,
    "language-bash": shellRules,
    "language-shell": shellRules
  };

  function langOf(code) {
    var cls = code.className || "";
    var m = cls.match(/language-([a-z]+)/);
    if (m) return m[1];
    return null;
  }

  function highlightAll() {
    var blocks = document.querySelectorAll("pre > code");
    for (var i = 0; i < blocks.length; i++) {
      var code = blocks[i];
      var lang = langOf(code);
      var rules = grammars["language-" + lang] || grammars[lang];
      if (!rules) continue;
      var raw = code.textContent;
      code.innerHTML = tokenize(raw, rules);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", highlightAll);
  } else {
    highlightAll();
  }

  window.SiteHighlight = { highlightAll: highlightAll };
})();
