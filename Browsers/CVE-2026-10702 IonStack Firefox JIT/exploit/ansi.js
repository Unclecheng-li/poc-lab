(function () {
  const colors = {
    31: "#d32f2f",
    32: "#2e7d32",
    33: "#f9a825",
  };

  window.renderAnsiToFragment = function (input, ownerDocument) {
    const doc = ownerDocument || document;
    const fragment = doc.createDocumentFragment();
    const text = String(input || "");
    const pattern = /(?:\x1b|\\033|\\x1b)\[([0-9;]*)m/g;
    let offset = 0;
    let color = "";

    function append(value) {
      if (!value) {
        return;
      }
      if (!color) {
        fragment.appendChild(doc.createTextNode(value));
        return;
      }
      const span = doc.createElement("span");
      span.style.color = color;
      span.appendChild(doc.createTextNode(value));
      fragment.appendChild(span);
    }

    for (;;) {
      const match = pattern.exec(text);
      if (!match) {
        break;
      }
      append(text.slice(offset, match.index));
      offset = pattern.lastIndex;

      const raw = match[1] || "0";
      const parts = raw.split(";");
      for (let i = 0; i < parts.length; i++) {
        const code = Number(parts[i] || "0");
        if (code === 0) {
          color = "";
        } else if (Object.prototype.hasOwnProperty.call(colors, code)) {
          color = colors[code];
        }
      }
    }

    append(text.slice(offset));
    return fragment;
  };
}());
