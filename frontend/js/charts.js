// Small SVG line charts with a crosshair tooltip, keyboard support and a data
// table, built without a chart library so the demo works offline.

const NS = "http://www.w3.org/2000/svg";

function el(name, attrs = {}, parent) {
  const node = document.createElementNS(NS, name);
  for (const [k, v] of Object.entries(attrs)) node.setAttribute(k, String(v));
  if (parent) parent.appendChild(node);
  return node;
}

function niceTicks(max, count = 5) {
  const raw = max / count;
  const mag = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 2.5, 5, 10].map((m) => m * mag).find((s) => s >= raw);
  const ticks = [];
  for (let v = 0; v <= max + step * 0.001; v += step) ticks.push(v);
  if (ticks[ticks.length - 1] < max) ticks.push(ticks[ticks.length - 1] + step);
  return ticks;
}

/**
 * opts: {series:[{name, color, points:[{x,y}]}], xLabel, yLabel, xLog, xTicks,
 *        xFormat, yFormat, shadeFrom, shadeLabel, caption}
 */
export function lineChart(host, opts) {
  const W = 640;
  const H = 300;
  const m = { l: 58, r: 96, t: 14, b: 46 };
  const iw = W - m.l - m.r;
  const ih = H - m.t - m.b;
  const xs = opts.series.flatMap((s) => s.points.map((p) => p.x));
  const ys = opts.series.flatMap((s) => s.points.map((p) => p.y));
  const [x0, x1] = [Math.min(...xs), Math.max(...xs)];
  const yTicks = niceTicks(Math.max(...ys));
  const yMax = yTicks[yTicks.length - 1];
  const fx = opts.xLog
    ? (x) => m.l + ((Math.log10(x) - Math.log10(x0)) / (Math.log10(x1) - Math.log10(x0))) * iw
    : (x) => m.l + ((x - x0) / (x1 - x0)) * iw;
  const fy = (y) => m.t + ih - (y / yMax) * ih;
  const xf = opts.xFormat || ((v) => String(v));
  const yf = opts.yFormat || ((v) => String(v));

  const wrap = document.createElement("div");
  wrap.className = "chart";

  const legend = document.createElement("ul");
  legend.className = "chart-legend";
  if (opts.series.length > 1) {
    for (const s of opts.series) {
      const li = document.createElement("li");
      const key = document.createElement("span");
      key.className = "line-key";
      key.style.backgroundColor = s.color;
      li.append(key, document.createTextNode(s.name));
      legend.append(li);
    }
    wrap.append(legend);
  }

  const frame = document.createElement("div");
  frame.className = "chart-frame";
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": opts.caption, tabindex: 0 });
  frame.append(svg);
  wrap.append(frame);

  if (opts.shadeFrom !== undefined) {
    const sx = fx(opts.shadeFrom);
    el("rect", { x: sx, y: m.t, width: m.l + iw - sx, height: ih, class: "chart-shade" }, svg);
    const t = el("text", { x: sx + 8, y: m.t + 16, class: "chart-note" }, svg);
    t.textContent = opts.shadeLabel;
  }

  for (const v of yTicks) {
    el("line", { x1: m.l, x2: m.l + iw, y1: fy(v), y2: fy(v), class: v === 0 ? "chart-base" : "chart-grid" }, svg);
    const t = el("text", { x: m.l - 8, y: fy(v) + 4, class: "chart-tick", "text-anchor": "end" }, svg);
    t.textContent = yf(v);
  }
  for (const v of opts.xTicks) {
    const t = el("text", { x: fx(v), y: m.t + ih + 18, class: "chart-tick", "text-anchor": "middle" }, svg);
    t.textContent = xf(v);
  }
  const xl = el("text", { x: m.l + iw / 2, y: H - 6, class: "chart-axis", "text-anchor": "middle" }, svg);
  xl.textContent = opts.xLabel;
  const yl = el("text", { x: 14, y: m.t + ih / 2, class: "chart-axis", "text-anchor": "middle", transform: `rotate(-90 14 ${m.t + ih / 2})` }, svg);
  yl.textContent = opts.yLabel;

  for (const s of opts.series) {
    const d = s.points.map((p, i) => `${i ? "L" : "M"}${fx(p.x).toFixed(1)},${fy(p.y).toFixed(1)}`).join("");
    el("path", { d, fill: "none", stroke: s.color, "stroke-width": 2, "stroke-linejoin": "round", "stroke-linecap": "round" }, svg);
    const last = s.points[s.points.length - 1];
    el("circle", { cx: fx(last.x), cy: fy(last.y), r: 4, fill: s.color, stroke: "#000", "stroke-width": 2 }, svg);
    const t = el("text", { x: fx(last.x) + 9, y: fy(last.y) + 4 + (s.labelDy || 0), class: "chart-direct" }, svg);
    t.textContent = s.short || s.name;
  }

  // Crosshair + tooltip
  const allX = [...new Set(xs)].sort((a, b) => a - b);
  const hair = el("line", { y1: m.t, y2: m.t + ih, class: "chart-hair", visibility: "hidden" }, svg);
  const dots = opts.series.map((s) => el("circle", { r: 4, fill: s.color, stroke: "#000", "stroke-width": 2, visibility: "hidden" }, svg));
  const tip = document.createElement("div");
  tip.className = "chart-tip";
  tip.hidden = true;
  frame.append(tip);
  const hit = el("rect", { x: m.l, y: m.t, width: iw, height: ih, fill: "transparent" }, svg);

  let index = -1;
  function show(i) {
    index = Math.max(0, Math.min(allX.length - 1, i));
    const x = allX[index];
    hair.setAttribute("x1", fx(x));
    hair.setAttribute("x2", fx(x));
    hair.setAttribute("visibility", "visible");
    tip.replaceChildren();
    const head = document.createElement("div");
    head.className = "chart-tip-head";
    head.textContent = `${opts.xName || opts.xLabel}: ${xf(x)}`;
    tip.append(head);
    opts.series.forEach((s, k) => {
      const p = s.points.find((q) => q.x === x);
      dots[k].setAttribute("visibility", p ? "visible" : "hidden");
      const row = document.createElement("div");
      row.className = "chart-tip-row";
      const key = document.createElement("span");
      key.className = "line-key";
      key.style.backgroundColor = s.color;
      const val = document.createElement("strong");
      val.textContent = p ? yf(p.y) : "—";
      const name = document.createElement("span");
      name.textContent = p ? s.name : `${s.name}: not accepted`;
      row.append(key, val, name);
      tip.append(row);
      if (p) {
        dots[k].setAttribute("cx", fx(p.x));
        dots[k].setAttribute("cy", fy(p.y));
      }
    });
    tip.hidden = false;
    const left = (fx(x) / W) * 100;
    tip.classList.toggle("flip", left > 60);
    tip.style.left = `${left}%`;
  }
  function hide() {
    hair.setAttribute("visibility", "hidden");
    dots.forEach((d) => d.setAttribute("visibility", "hidden"));
    tip.hidden = true;
  }
  hit.addEventListener("pointermove", (e) => {
    const box = svg.getBoundingClientRect();
    const px = ((e.clientX - box.left) / box.width) * W;
    let best = 0;
    allX.forEach((x, i) => {
      if (Math.abs(fx(x) - px) < Math.abs(fx(allX[best]) - px)) best = i;
    });
    show(best);
  });
  hit.addEventListener("pointerleave", hide);
  svg.addEventListener("focus", () => show(index < 0 ? 0 : index));
  svg.addEventListener("blur", hide);
  svg.addEventListener("keydown", (e) => {
    if (e.key === "ArrowRight") show(index + 1);
    else if (e.key === "ArrowLeft") show(index - 1);
    else return;
    e.preventDefault();
  });

  // Data table: every value is reachable without hovering.
  const details = document.createElement("details");
  details.className = "chart-table";
  const summary = document.createElement("summary");
  summary.textContent = "Show the numbers";
  const table = document.createElement("table");
  const thead = table.createTHead().insertRow();
  [opts.xName || opts.xLabel, ...opts.series.map((s) => s.name)].forEach((h) => {
    const th = document.createElement("th");
    th.textContent = h;
    thead.append(th);
  });
  const tbody = table.createTBody();
  for (const x of allX) {
    const row = tbody.insertRow();
    row.insertCell().textContent = xf(x);
    for (const s of opts.series) {
      const p = s.points.find((q) => q.x === x);
      row.insertCell().textContent = p ? yf(p.y) : "rejected";
    }
  }
  details.append(summary, table);
  wrap.append(details);
  host.replaceChildren(wrap);
}
