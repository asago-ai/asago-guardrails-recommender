/* ASAGO recommender demo (static replay). Vanilla JS, no build step.
   Data comes from data/snapshot.js (window.ASAGO_SNAPSHOT) so the page works from file://.
   All data is untrusted text: everything goes through esc() before innerHTML. */
(function () {
  "use strict";

  const SNAP = (typeof window !== "undefined" && window.ASAGO_SNAPSHOT) || { use_cases: [], catalog: { rails: [] }, summary: {} };

  /* ---------- helpers ---------- */
  const ESC = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
  const esc = (v) => String(v == null ? "" : v).replace(/[&<>"']/g, (c) => ESC[c]);
  const chip = (t, cls = "") => `<span class="chip ${cls}">${esc(t)}</span>`;
  const chips = (arr, cls) => (arr || []).map((t) => chip(t, cls)).join("") || '<span class="muted">none</span>';
  const clip = (s, n) => { s = String(s == null ? "" : s); return s.length > n ? s.slice(0, n - 1) + "…" : s; };
  const note = (title, text) => `<div class="note" role="note"><b>${esc(title)}</b> ${esc(text)}</div>`;
  const kv = (k, v) => `<div class="kv"><span class="k">${esc(k)}</span><span class="v">${v}</span></div>`;
  const metric = (value, label, mint) => `<div class="metric ${mint ? "mint" : ""}"><strong>${esc(value)}</strong><span>${esc(label)}</span></div>`;
  const metrics = (arr) => `<div class="metrics">${arr.join("")}</div>`;
  const det = (key, title, body) =>
    `<details class="deep" data-k="${esc(key)}" ${state.open.has(key) ? "open" : ""}><summary>${esc(title)}</summary><div class="deep-body">${body}</div></details>`;
  const bars = (rows, max) =>
    `<div class="bars">${rows.map((r) => `<div class="barrow"><span class="bl" title="${esc(r.label)}">${esc(r.label)}</span><span class="bt"><i style="width:${max ? Math.max(3, Math.round((100 * r.value) / max)) : 0}%"></i></span><span class="bv">${esc(r.text != null ? r.text : r.value)}</span></div>`).join("")}</div>`;

  /* ---------- data accessors (no DOM) ---------- */
  const Data = {
    snapshot: SNAP,
    useCases: () => SNAP.use_cases,
    rails: () => SNAP.catalog.rails,
    railName(id) { const r = SNAP.catalog.rails.find((x) => x.id === id); return r ? r.name : id; },
    risks: (uc) => (uc.policy && uc.policy.risks) || [],
    threats: (uc) => (uc.battery && uc.battery.threats) || [],
    patternCount: (uc) => Data.threats(uc).reduce((n, t) => n + (t.attack_patterns || []).length, 0),
    scenarios: (uc) => uc.scenarios || [],
    attacks: (uc) => uc.attacks || [],
    isUntagged: (a) => !(a.signals || []).length && !(a.candidates || []).length && !(a.tests || []).length,
    options: (a) => (a.recommendation && a.recommendation.options) || [],
    isGap: (a) => !!a.recommendation && a.recommendation.status === "gap",
    recommendedRails(a) { const s = new Set(); Data.options(a).forEach((o) => (o.rails || []).forEach((r) => s.add(r))); return s; },
    blockedByAny(a) { return (a.tests || []).length ? a.tests.some((x) => x.status === "blocked") : null; },
    blockedCount: (uc) => Data.attacks(uc).filter((a) => Data.blockedByAny(a)).length,
    threatName(uc, id) {
      const t = Data.threats(uc).find((x) => x.threat_id === id);
      if (t) return t.threat_name;
      const s = Data.scenarios(uc).find((x) => x.threat_id === id);
      return s ? s.threat_name : id;
    },
    /* per threat: attack patterns, scenarios generated, scenarios that passed the gate (= attacks built) */
    perThreat(uc) {
      const ids = [];
      const add = (id) => { if (id && !ids.includes(id)) ids.push(id); };
      Data.threats(uc).forEach((t) => add(t.threat_id));
      Data.scenarios(uc).forEach((s) => add(s.threat_id));
      return ids.map((id) => {
        const th = Data.threats(uc).find((x) => x.threat_id === id);
        return {
          id, name: Data.threatName(uc, id), patterns: th ? (th.attack_patterns || []).length : 0,
          generated: Data.scenarios(uc).filter((s) => s.threat_id === id).length,
          gated: Data.attacks(uc).filter((a) => a.threat_id === id).length,
        };
      });
    },
    perRail(uc) {
      const m = {};
      Data.attacks(uc).forEach((a) =>
        (a.tests || []).filter((t) => (t.rails || []).length === 1).forEach((t) => {
          const r = (m[t.rails[0]] = m[t.rails[0]] || { id: t.rails[0], tested: 0, blocked: 0 });
          r.tested++;
          if (t.status === "blocked") r.blocked++;
        })
      );
      return Object.values(m).sort((x, y) => y.blocked - x.blocked || y.tested - x.tested);
    },
    prov: (uc, k) => ((uc.provenance && uc.provenance.stages) || {})[k] || {},
    replayDate() {
      const d = new Date(SNAP.generated_at);
      return isNaN(d) ? String(SNAP.generated_at || "") : d.toISOString().slice(0, 10);
    },
  };

  const shortId = (a) => a.short_id || String(a.attack_id).slice(-8);
  const stateOf = (a) => (Data.isUntagged(a) ? "na" : Data.blockedByAny(a) ? "blocked" : "open");
  const stateLabel = (a) => ({ na: "Untagged", blocked: "Blocked", open: "Not blocked" })[stateOf(a)];

  /* ---------- state ---------- */
  const state = {
    uc: 0,
    done: 0, // stages completed (0-4)
    running: -1, // stage index currently running
    sub: 0, // sub-steps completed in the running stage
    sel: 0, // stage shown in the bottom panel
    tab: {}, // stage -> sub-component index
    attack: 0,
    open: new Set(),
    sfilter: "",
    sshown: 20,
    scn: null,
    risk: null,
    runAll: false,
    paused: false, // deep-link snapshots do not advance
    timer: null,
  };
  const curUC = () => Data.useCases()[state.uc];
  const curAttack = () => Data.attacks(curUC())[state.attack] || null;

  /* ---------- sub-component renderers (c = { uc, a }) ---------- */
  function attackPicker(c, badges) {
    const list = Data.attacks(c.uc);
    return `<div class="picker" role="group" aria-label="Attack"><span class="picker-label">Attack</span>${list.map((a, i) => {
      const st = badges ? stateOf(a) : "plain";
      const label = badges ? ` (${stateLabel(a)})` : "";
      return `<button type="button" class="pick ${i === state.attack ? "on" : ""} ${st}" data-act="attack" data-i="${i}" aria-pressed="${i === state.attack}" title="${esc(a.threat_id + " · " + a.attack_pattern_name + label)}"><i></i>${esc(shortId(a))}</button>`;
    }).join("")}${badges ? '<span class="picker-legend"><i class="dot blocked"></i>Blocked <i class="dot open"></i>Not blocked <i class="dot na"></i>Untagged</span>' : ""}</div>`;
  }

  const pol = (c) => c.uc.policy || {};
  const polStats = (c) => pol(c).stats || {};
  const num = (v) => (v == null ? "n/a" : Number(v).toLocaleString("en-US"));

  /* ---- 01 Policy Mapper ---- */
  function parseHTML(c) {
    const p = pol(c), st = polStats(c);
    return metrics([metric(num(st.chunks), "policy chunks"), metric(num(p.risks_total), "risks in the output", true), metric(st.model || "n/a", "LLM")]) +
      `<p class="muted small">Policy document: ${esc(p.name || Data.prov(c.uc, "policy").source_doc || "")}. The document is parsed and split into chunks; each chunk is matched against the risk taxonomies in the next step.</p>` +
      note("Output of this stage.", "The policy mapper produces risk-extraction.json and report.html only: risks with evidence, causal chains and mitigations. It does not build a threat surface.");
  }
  function retrieveHTML(c) {
    const st = polStats(c);
    return `<div class="pair"><div><strong>${esc(num(st.candidates_retrieved))}</strong><span>candidate matches</span></div><span class="arrow" aria-hidden="true">→</span><div><strong>${esc(num(Data.prov(c.uc, "policy").outputs && Data.prov(c.uc, "policy").outputs.risks))}</strong><span>risks kept</span></div></div>` +
      metrics([metric(num(st.auto_accepted), "auto-accepted by score"), metric(num(st.llm_judged), "borderline, judged by the LLM", true), metric(num(st.grounding_filtered), "dropped for weak grounding")]) +
      '<p class="muted small">Candidates come from BM25, embeddings and a cross-encoder over about 524 Nexus risks. Borderline ones go to an LLM judge.</p>';
  }
  function groundHTML(c) {
    const rs = Data.risks(c.uc), p = pol(c);
    const tax = new Set(rs.map((r) => r.taxonomy));
    const rows = rs.map((r) => {
      const open = state.risk === r.id;
      return `<tr class="click ${open ? "sel" : ""}" data-act="risk" data-id="${esc(r.id)}" tabindex="0"><td>${esc(r.name)}</td><td>${chip(r.taxonomy)}</td><td><span class="badge ${r.grounding_confidence === "high" ? "pass" : "saved"}">${esc(r.grounding_confidence || "n/a")}</span></td><td>${esc(r.evidence_total != null ? r.evidence_total : (r.evidence || []).length)}</td></tr>` +
        (open ? `<tr class="detail"><td colspan="4">${(r.evidence || []).map((e) => `<blockquote>${esc(e)}</blockquote>`).join("") || '<p class="muted">No evidence quoted.</p>'}</td></tr>` : "");
    }).join("");
    return metrics([metric(num(p.risks_total != null ? p.risks_total : rs.length), "risks extracted"), metric(rs.filter((r) => r.grounding_confidence === "high").length + " of " + rs.length, "shown with high grounding", true), metric(tax.size, "taxonomies shown")]) +
      `<p class="muted small">Showing the first ${rs.length} risks. Click a row for the policy text each risk is grounded in.</p>` +
      `<div class="tablewrap"><table class="t"><thead><tr><th>Risk</th><th>Taxonomy</th><th>Grounding</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table></div>`;
  }
  function chainHTML(c) {
    const rs = Data.risks(c.uc), st = polStats(c);
    const part = (k, v) => (v ? `<div class="chain-step"><b>${esc(k)}</b><span>${esc(v)}</span></div>` : "");
    return metrics([metric(num(st.with_causal_chain), "risks with a causal chain", true), metric(num(pol(c).risks_total), "risks in the output")]) +
      '<p class="muted small">Each risk is expanded into threat → vulnerability → consequence, with its impact and suggested mitigations.</p>' +
      rs.map((r) => {
        const has = r.threat || r.vulnerability || r.consequence;
        const mits = (r.mitigations || []).map((m) => `<li><b>${esc(m.name)}</b> ${esc(m.description)}</li>`).join("");
        return `<details class="row-card"><summary><span class="rc-title">${esc(r.name)}</span><span class="rc-meta">${chip(r.taxonomy)}${has ? "" : '<span class="muted small">no chain</span>'}</span></summary><div class="rc-body">${has ? `<div class="chain">${part("Threat", r.threat)}<span class="arrow" aria-hidden="true">→</span>${part("Vulnerability", r.vulnerability)}<span class="arrow" aria-hidden="true">→</span>${part("Consequence", r.consequence)}</div>${part("Threat source", r.threat_source)}${part("Impact", r.impact)}` : '<p class="muted">No causal chain recorded.</p>'}${mits ? `<h4 class="sub">Mitigations${r.mitigations_total > (r.mitigations || []).length ? " (first " + r.mitigations.length + " of " + esc(r.mitigations_total) + ")" : ""}</h4><ul>${mits}</ul>` : ""}</div></details>`;
      }).join("");
  }

  /* ---- 02 Scenario Generator ---- */
  const scnDetail = (c) => Data.prov(c.uc, "scenarios").detail || {};
  function mapHTML(c) {
    const ts = Data.threats(c.uc), b = c.uc.battery || {};
    return metrics([metric(ts.length, "threats"), metric(Data.patternCount(c.uc), "attack patterns", true), metric(b.risk_cards != null ? b.risk_cards : Data.risks(c.uc).length, "risk cards mapped")]) +
      '<p class="muted small">Input: the policy mapper output, the use-case profile and qualification facts. Risks are mapped to threats (SSSOM), giving threat-surface.yaml: the threats and their attack patterns.</p>' +
      ts.map((t) => `<details class="row-card"><summary><span class="rc-title">${esc(t.threat_name)}</span><span class="rc-meta">${chip(t.threat_id)}<span class="muted small">${(t.attack_patterns || []).length} patterns</span></span></summary><div class="rc-body">${chips(t.attack_patterns)}<p class="muted small">Mapped from ${esc(t.risks_mapped != null ? t.risks_mapped : "?")} risk card(s).</p></div></details>`).join("");
  }
  function qualifyHTML(c) {
    const d = scnDetail(c), b = c.uc.battery || {};
    const pf = d.rule_prefilter, ep = d.entry_points;
    return `<div class="pair"><div><strong>${esc(b.attack_patterns_total != null ? b.attack_patterns_total : Data.patternCount(c.uc))}</strong><span>attack patterns</span></div><span class="arrow" aria-hidden="true">→</span><div><strong>${esc(num(d.candidates_attempted))}</strong><span>candidate scenarios</span></div></div>` +
      metrics([metric(ep ? ep.accessible + " of " + ep.total : "n/a", "attacker-accessible entry points"), metric(pf ? pf.rejected + " of " + pf.candidates : "n/a", "rejected by deterministic rules", true), metric((d.uncovered_attack_patterns || []).length, "patterns left uncovered")]) +
      '<p class="muted small">Attack patterns are qualified against the use-case profile, then crossed with entry points and techniques to enumerate candidate scenarios. Deterministic rules reject impossible candidates before the LLM sees them.</p>' +
      ((d.seeds_without_techniques || []).length ? `<h4 class="sub">Skipped: no technique IDs</h4><div class="chiprow">${chips(d.seeds_without_techniques)}</div>` : "") +
      ((d.uncovered_attack_patterns || []).length ? `<h4 class="sub">Uncovered attack patterns</h4><div class="chiprow">${chips(d.uncovered_attack_patterns)}</div>` : "");
  }
  function scenariosHTML(c) {
    const all = Data.scenarios(c.uc), d = scnDetail(c);
    const pt = Data.perThreat(c.uc).filter((p) => p.generated);
    const max = Math.max(1, ...pt.map((p) => p.generated));
    const list = all.filter((s) => !state.sfilter || s.threat_id === state.sfilter);
    const shown = list.slice(0, state.sshown);
    const rows = shown.map((s) => {
      const id = s.scenario_id;
      const open = state.scn === id;
      return `<tr class="click ${open ? "sel" : ""}" data-act="scn" data-id="${esc(id)}" tabindex="0"><td class="mono">${esc(String(id).slice(-8))}</td><td>${chip(s.threat_id)}</td><td>${esc(clip(s.attack_pattern_name, 70))}</td><td>${esc(s.actor_type || "")}</td></tr>` +
        (open ? `<tr class="detail"><td colspan="4"><p>${esc(s.narrative_summary)}</p><ol>${(s.steps || []).map((x) => `<li>${esc(x)}</li>`).join("")}</ol><p class="muted small">Entry point: ${esc(s.entry_point || "n/a")}</p></td></tr>` : "");
    }).join("");
    return metrics([metric(num(d.enumerated), "candidates attempted"), metric(all.length, "scenarios generated and admitted", true), metric(pt.length, "threats covered")]) +
      '<h4 class="sub">Admitted scenarios per threat</h4>' +
      `<div class="bars">${pt.map((p) => `<button type="button" class="bar-button" data-act="sfilter" data-v="${esc(p.id)}" aria-pressed="${state.sfilter === p.id}"><span title="${esc(p.name)}">${esc(p.id)}</span><b style="width:${Math.max(3, Math.round((100 * p.generated) / max))}%"></b><strong>${p.generated}</strong></button>`).join("")}</div>` +
      `<div class="filter-row"><label class="muted small" for="sf">Threat</label><select id="sf" data-act="sfilter-sel"><option value="">All threats (${all.length})</option>${pt.map((p) => `<option value="${esc(p.id)}" ${state.sfilter === p.id ? "selected" : ""}>${esc(p.id + " · " + clip(p.name, 50))} (${p.generated})</option>`).join("")}</select><small>${list.length} shown of ${all.length}. Click a row for the narrative.</small></div>` +
      `<div class="tablewrap"><table class="t"><thead><tr><th>Scenario</th><th>Threat</th><th>Attack pattern</th><th>Actor</th></tr></thead><tbody>${rows}</tbody></table></div>` +
      (list.length > shown.length ? `<p><button type="button" class="secondary" data-act="more">Show more (${list.length - shown.length} left)</button></p>` : "");
  }
  function admissionHTML(c) {
    const p = Data.prov(c.uc, "scenarios"), d = p.detail || {};
    const pt = Data.perThreat(c.uc).filter((x) => x.generated);
    const max = Math.max(1, ...pt.map((x) => x.generated));
    const reasons = d.quarantine_reasons || [];
    return metrics([metric(num(p.generated), "candidates"), metric(num(p.admitted), "admitted", true), metric(num(p.quarantined), "quarantined")]) +
      '<p class="muted small">Every candidate goes through the admission gates. Admitted scenarios are kept; rejected or failed candidates are quarantined.</p>' +
      '<h4 class="sub">Admitted per threat</h4>' +
      bars(pt.map((x) => ({ label: x.id + " " + clip(x.name, 38), value: x.generated })), max) +
      '<p class="muted small">Quarantined candidates are not tagged with a threat in the run output, so only admitted scenarios are split by threat.</p>' +
      `<h4 class="sub">Why candidates were quarantined (${esc(num(p.quarantined))}: ${esc(num(d.rejected))} rejected, ${esc(num(d.generation_failed))} failed generation)</h4>` +
      `<div class="tablewrap"><table class="t"><thead><tr><th>Reason</th><th>Candidates</th></tr></thead><tbody>${reasons.map((r) => `<tr><td class="mono">${esc(r.code)}</td><td>${esc(r.count)}</td></tr>`).join("")}</tbody></table></div>` +
      det("gates", "Gates checked (" + (d.gates || []).length + ")", `<div class="chiprow">${chips(d.gates)}</div>`);
  }

  /* ---- 03 Artifact Generator ---- */
  const artProv = (c) => Data.prov(c.uc, "artifacts");
  function funnelHTML(c) {
    const p = artProv(c);
    const pt = (p.per_threat || []).filter((t) => t.admitted);
    const max = Math.max(1, ...pt.map((t) => t.admitted));
    return metrics([metric(num(p.admitted_input), "admitted scenarios in"), metric(num(p.attempted), "artifacts attempted", true), metric(num(p.produced), "artifacts produced")]) +
      note("Where the cut happens.", p.selection_rule || "") +
      '<h4 class="sub">Admitted scenarios vs artifacts, per threat</h4>' +
      `<div class="bars gate">${pt.map((t) => `<div class="barrow"><span class="bl" title="${esc(t.name)}">${esc(t.threat_id)}</span><span class="bt"><i class="gen" style="width:${Math.max(3, Math.round((100 * t.admitted) / max))}%"></i>${t.artifacts ? `<i class="pass" style="width:${Math.max(2, Math.round((100 * t.artifacts) / max))}%"></i>` : ""}</span><span class="bv">${esc(t.artifacts)} / ${esc(t.admitted)}</span></div>`).join("")}</div>` +
      '<p class="legend"><i class="dot gen"></i>admitted scenarios <i class="dot pass"></i>with an artifact</p>';
  }
  /* attack_turn_index is the 0-based index into a.turns (taken from the garak artifact); fall back to a text match */
  function attackTurn(a) {
    const ts = a.turns || [];
    if (Number.isInteger(a.attack_turn_index) && ts[a.attack_turn_index]) return a.attack_turn_index;
    const key = String(a.adversarial_text || "").slice(0, 40);
    const m = key ? ts.findIndex((t) => String(t.content || "").includes(key)) : -1;
    if (m >= 0) return m;
    for (let i = ts.length - 1; i >= 0; i--) if (ts[i].role === "user") return i;
    return -1;
  }
  function turnsHTML(a) {
    const hot = attackTurn(a);
    return `<div class="conversation">${(a.turns || []).map((t, i) => `<div class="turn ${i === hot ? "attack" : ""}"><header><span>${esc(t.role)}${t.tool_calls && t.tool_calls.length ? " · calls " + esc(t.tool_calls.join(", ")) : ""}</span>${i === hot ? '<span class="badge">attack turn</span>' : ""}</header><pre>${esc(t.content)}</pre></div>`).join("") || '<p class="muted">No transcript.</p>'}</div>`;
  }
  function rubricHTML(a) {
    const r = a.detector_rubric;
    if (!r) return '<p class="muted">No detector rubric recorded.</p>';
    if (typeof r === "string") return `<p>${esc(r)}</p>`;
    let h = "";
    if (r.context) h += `<h4 class="sub">Context</h4><p>${esc(r.context)}</p>`;
    const rb = r.rubrics || {};
    const keys = Object.keys(rb);
    if (keys.length) h += `<div class="rubrics">${keys.map((k) => `<div><h3>${esc(k.replace(/_/g, " "))}</h3><ul>${(Array.isArray(rb[k]) ? rb[k] : [rb[k]]).map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>`).join("")}</div>`;
    if (r.judge_prompt) h += det("judge", "Judge prompt", `<pre class="code">${esc(r.judge_prompt)}</pre>`);
    return h || '<p class="muted">Rubric is empty.</p>';
  }
  function conversationHTML(c) {
    const a = c.a;
    if (!a) return funnelHTML(c) + '<p class="muted">No attacks.</p>';
    return funnelHTML(c) + '<h4 class="sub">Attack conversations</h4>' + attackPicker(c, state.done >= 4) +
      `<div class="kvs">${kv("Threat", chip(a.threat_id) + " " + esc(a.threat_name))}${kv("Attack pattern", esc(a.attack_pattern_name))}${kv("Injection surface", chip(a.injection_surface || "unknown"))}</div>` +
      `<h4 class="sub">Multi-turn conversation (with tool context)</h4>${turnsHTML(a)}` +
      det("narr", "Narrative", `<p>${esc(a.narrative_summary)}</p>`);
  }
  function validationHTML(c) {
    const a = c.a, p = artProv(c);
    if (!a) return '<p class="muted">No attacks.</p>';
    const v = a.artifact || {};
    const cg = p.coverage_gate || {};
    return metrics([metric(num(p.validated) + " of " + num(p.attempted), "pass fidelity validation", true), metric(p.fidelity_min != null ? p.fidelity_min + " / 12" : "n/a", "lowest fidelity score"), metric(Object.keys(cg).map((k) => cg[k] + " " + k).join(", ") || "n/a", "coverage gate")]) +
      '<p class="muted small">Validation checks the conversation structure and scores fidelity to the scenario (acceptance needs at least 10 of 12 and no critical violations). The coverage gate says how well Garak can observe the attack.</p>' +
      attackPicker(c, state.done >= 4) +
      `<div class="kvs">${kv("Validation", chip(v.validated ? "passed" : "not validated", v.validated ? "ess" : "bad"))}${kv("Fidelity", esc(v.fidelity_total != null ? v.fidelity_total + " / 12" : "n/a"))}${kv("Attempts", esc(v.attempts != null ? v.attempts : "n/a"))}${kv("Coverage gate", chip(v.coverage_gate || "n/a") + " " + esc(v.coverage_reason || ""))}</div>` +
      (v.scores ? `<div class="chiprow">${Object.keys(v.scores).map((k) => chip(k.replace(/_/g, " ") + " " + v.scores[k] + "/2")).join("")}</div>` : "") +
      `<h4 class="sub">Detector rubric (how success is judged)</h4>${rubricHTML(a)}`;
  }
  function baselineHTML(c) {
    const p = artProv(c), b = p.baseline || {}, o = b.outcomes || {};
    const list = Data.attacks(c.uc);
    const a = c.a;
    return note("Separate script.", "The baseline is not part of the artifact generator. pipeline_automation/run_baseline_test.py runs each artifact against the target model with no guardrails and records baseline_outcome.") +
      metrics([metric(o.attack_succeeded || 0, "attack_succeeded", true), metric(o.attack_not_demonstrated || 0, "attack_not_demonstrated"), metric(list.length, "artifacts run")]) +
      `<p class="muted small">Target: ${esc(b.target || "n/a")}.</p>` +
      (a ? attackPicker(c, state.done >= 4) + `<div class="kvs">${kv("Baseline (no rails)", chip(a.baseline_outcome || "unknown", a.baseline_outcome === "attack_succeeded" ? "bad" : ""))}</div>` : "") +
      `<div class="tablewrap"><table class="t"><thead><tr><th>Attack</th><th>Pattern</th><th>Baseline outcome</th></tr></thead><tbody>${list.map((x, i) => `<tr class="click ${i === state.attack ? "sel" : ""}" data-act="attack" data-i="${i}" tabindex="0"><td class="mono">${esc(shortId(x))}</td><td>${esc(clip(x.attack_pattern_name, 60))}</td><td>${chip(x.baseline_outcome || "unknown", x.baseline_outcome === "attack_succeeded" ? "bad" : "")}</td></tr>`).join("")}</tbody></table></div>`;
  }

  const untaggedNote = (a) => note("Attack " + shortId(a) + " was not tagged.", "The signal tagger produced nothing for it, so it has no signals, candidates, recommendation or tests.");
  function signalsHTML(c) {
    const a = c.a;
    if (!a) return "";
    let h = attackPicker(c, state.done >= 4);
    if (Data.isUntagged(a)) return h + untaggedNote(a);
    const sg = a.signals || [];
    h += metrics([metric(sg.length, "signals tagged"), metric(sg.filter((s) => s.role === "essential").length, "essential", true), metric(sg.filter((s) => s.role !== "essential").length, "supporting")]);
    h += `<div class="chiprow">${sg.map((s) => chip(s.signal, s.role === "essential" ? "ess" : "")).join("")}</div>`;
    h += det("sig", "Evidence for each signal", `<table class="t"><thead><tr><th>Signal</th><th>Role</th><th>Source</th><th>Evidence</th></tr></thead><tbody>${sg.map((s) => `<tr><td>${esc(s.signal)}</td><td>${esc(s.role)}</td><td>${esc(s.source)}</td><td>${esc(clip(s.evidence, 260))}</td></tr>`).join("")}</tbody></table>`);
    return h;
  }
  function poolHTML(c) {
    const a = c.a;
    if (!a) return "";
    let h = attackPicker(c, state.done >= 4);
    if (Data.isUntagged(a)) return h + untaggedNote(a);
    const rails = Data.rails();
    const cm = {}; (a.candidates || []).forEach((x) => (cm[x.rail_id] = x));
    const rec = Data.recommendedRails(a);
    const byType = {};
    rails.forEach((r) => (byType[r.type] = byType[r.type] || []).push(r));
    const grid = Object.keys(byType).sort().map((t) => `<h4 class="sub">${esc(t)} <span class="muted">(${byType[t].length})</span></h4><div class="railgrid">${byType[t].map((r) => {
      const k = cm[r.id];
      return `<div class="rail ${rec.has(r.id) ? "rec" : k ? "cand" : ""}" title="${esc(r.id)}"><b>${esc(r.name)}</b>${k ? `<small>${esc((k.matched_signals || []).join(", "))}</small>` : ""}</div>`;
    }).join("")}</div>`).join("");
    h += `<div class="pair"><div><strong>${rails.length}</strong><span>rails in pool</span></div><span class="arrow" aria-hidden="true">→</span><div><strong>${(a.candidates || []).length}</strong><span>candidates</span></div></div>`;
    h += `<div class="chiprow">${(a.candidates || []).map((k) => chip(Data.railName(k.rail_id), rec.has(k.rail_id) ? "ess" : "")).join("") || '<span class="muted">No candidates.</span>'}</div>`;
    h += note("About the pool.", "64 catalog rails plus the built-in self_check_input_policy rail. Highlighted chips are in a recommended option.");
    h += det("grid", "All " + rails.length + " rails (candidates highlighted)", grid + '<p class="legend"><i class="dot cand"></i>candidate <i class="dot rec"></i>recommended</p>');
    return h;
  }
  function selectHTML(c) {
    const a = c.a;
    if (!a) return "";
    let h = attackPicker(c, state.done >= 4);
    if (Data.isUntagged(a)) return h + untaggedNote(a);
    const opts = Data.options(a);
    if (Data.isGap(a) || !opts.length) h += note("No rail covers this attack.", "The recommender reports a gap" + (a.recommendation && (a.recommendation.missing_signals || []).length ? " for: " + a.recommendation.missing_signals.join(", ") : "") + ".");
    h += metrics([metric(opts.length, "options"), metric(Data.recommendedRails(a).size, "rails used", true)]);
    h += opts.map((o) => {
      const nc = o.nemo_config || {};
      const yaml = (nc.config_yml ? "# config.yml\n" + nc.config_yml + "\n" : "") + (nc.rails_co ? "# rails.co\n" + nc.rails_co : "");
      return `<div class="row-card static"><div class="opt-head"><span class="rc-title">Option ${esc(o.rank)} · ${esc(o.config_name || "")}</span><span class="rc-meta">${chip("cost tier " + (o.cost_tier == null ? "?" : o.cost_tier))}${chip(o.evidence || "", "")}</span></div><div class="chiprow">${(o.rails || []).map((r) => chip(Data.railName(r), "ess")).join("")}${(o.covers_signals || []).map((s) => chip(s)).join("")}</div><p class="muted small">${esc(o.rationale)}</p>${det("nemo" + o.rank, "NeMo config", yaml ? `<pre class="code">${esc(yaml)}</pre>` : '<p class="muted">No NeMo config recorded.</p>')}</div>`;
    }).join("");
    return h;
  }
  function testHTML(c) {
    const a = c.a;
    if (!a) return "";
    let h = attackPicker(c, true);
    if (Data.isUntagged(a)) return h + untaggedNote(a);
    const tests = a.tests || [];
    if (tests.length === 0) {
      h += `<div class="muted"><span>Not tested in this snapshot.</span></div>`;
    } else {
      const blk = tests.find((t) => t.status === "blocked");
      h += `<div class="verdict ${blk ? "ok" : "bad"}"><strong>${blk ? "Blocked" : "Not blocked"}</strong><span>${blk ? "by " + esc(blk.blocking_rail || (blk.rails || []).map(Data.railName).join(" + ")) : "None of the recommended configs stopped it."}</span></div>`;
      h += `<div class="tablewrap"><table class="t"><thead><tr><th>Option</th><th>Test</th><th>Rails</th><th>Result</th><th>Latency</th></tr></thead><tbody>${tests.map((t) => `<tr><td>${esc(t.option_rank)}</td><td>${esc(t.test_label)}</td><td>${esc((t.rails || []).map(Data.railName).join(" + "))}</td><td><span class="pill ${t.status === "blocked" ? "ok" : "bad"}">${t.status === "blocked" ? "Blocked" : "Not blocked"}</span></td><td class="mono">${t.latency_ms == null ? "" : Math.round(t.latency_ms) + " ms"}</td></tr>`).join("")}</tbody></table></div><p class="muted small">Recorded status "modified" means the rail did not block the request, so it counts as not blocked.</p>`;
    }
    const pr = Data.perRail(c.uc);
    if (pr.length > 0) {
      const mx = Math.max(1, ...pr.map((r) => r.tested));
      h += det("perrail", "Per-rail summary (this use case)", `<div class="bars gate">${pr.map((r) => `<div class="barrow"><span class="bl" title="${esc(r.id)}">${esc(Data.railName(r.id))}</span><span class="bt"><i class="gen" style="width:${Math.max(3, Math.round((100 * r.tested) / mx))}%"></i>${r.blocked ? `<i class="pass" style="width:${Math.max(2, Math.round((100 * r.blocked) / mx))}%"></i>` : ""}</span><span class="bv">${r.blocked} / ${r.tested} blocked</span></div>`).join("")}</div><p class="legend"><i class="dot gen"></i>tested <i class="dot pass"></i>blocked</p>`);
    }
    h += det("allatk", "All attacks", `<div class="tablewrap"><table class="t"><thead><tr><th>Attack</th><th>Threat</th><th>Pattern</th><th>Result</th></tr></thead><tbody>${Data.attacks(c.uc).map((x, i) => `<tr class="click ${i === state.attack ? "sel" : ""}" data-act="attack" data-i="${i}" tabindex="0"><td class="mono">${esc(shortId(x))}</td><td>${chip(x.threat_id)}</td><td>${esc(clip(x.attack_pattern_name, 60))}</td><td><span class="pill ${stateOf(x) === "blocked" ? "ok" : stateOf(x) === "na" ? "na" : "bad"}">${esc(stateLabel(x))}</span></td></tr>`).join("")}</tbody></table></div>`);
    return h;
  }

  /* ---------- stages ---------- */
  const STAGES = [
    {
      key: "policy", name: "Policy Mapper", blurb: "Policy → risks + causal chains", title: "Risks and causal chains",
      desc: "Parse the policy, find the risks it implies, ground each in quoted text and explain how it could cause harm.", verb: "policy mapper",
      subs: [
        { key: "parse", label: "Parse policy", hint: "policy doc → chunks", msg: "parsing & chunking policy…", render: parseHTML },
        { key: "retrieve", label: "Retrieve & judge risks", hint: "BM25 + embeddings + cross-encoder, LLM judge", msg: "retrieving candidate risks…", render: retrieveHTML },
        { key: "ground", label: "Ground evidence", hint: "risks + quoted policy text", msg: "grounding evidence…", render: groundHTML },
        { key: "chains", label: "Causal chains", hint: "threat → vulnerability → consequence", msg: "synthesising causal chains…", render: chainHTML },
      ],
      summary: (c) => `${Data.risks(c.uc).length} risks`,
    },
    {
      key: "scenarios", name: "Scenario Generator", blurb: "Risks → threats → admitted scenarios", title: "Threat surface and scenarios",
      desc: "Map the risks to threats and attack patterns, enumerate candidate scenarios, generate them and admit those that pass the gates.", verb: "scenario generator",
      subs: [
        { key: "map", label: "Map risks to threats", hint: "threat surface: threats + attack patterns", msg: "mapping risks to threats…", render: mapHTML },
        { key: "qualify", label: "Qualify & enumerate", hint: "patterns → candidate scenarios", msg: "qualifying attack patterns and enumerating candidates…", render: qualifyHTML },
        { key: "generate", label: "Generate scenarios", hint: "narratives per threat", msg: "generating scenarios…", render: scenariosHTML },
        { key: "admit", label: "Admission gates", hint: "admitted vs quarantined", msg: "running admission gates…", render: admissionHTML },
      ],
      summary: (c) => `${Data.threats(c.uc).length} threats · ${Data.scenarios(c.uc).length} scenarios`,
    },
    {
      key: "artifacts", name: "Artifact Generator", blurb: "Scenarios → attack conversations", title: "Attack artifacts",
      desc: "Turn admitted scenarios into runnable multi-turn attack conversations with a detector rubric, validate them, then run a no-guardrails baseline.", verb: "artifact generator",
      subs: [
        { key: "build", label: "Build conversations", hint: "scenario → multi-turn conversation", msg: "building conversations…", render: conversationHTML },
        { key: "validate", label: "Rubric & validation", hint: "fidelity + coverage gate", msg: "writing rubrics and validating…", render: validationHTML },
        { key: "baseline", label: "Baseline (no guardrails)", hint: "separate script: run_baseline_test.py", msg: "running baseline without guardrails…", render: baselineHTML },
      ],
      summary: (c) => `${Data.attacks(c.uc).length} attacks`,
    },
    {
      key: "recommender", name: "Guardrail Recommender", blurb: "Attacks → minimal config → NeMo test", title: "Guardrail recommendation",
      desc: "Tag each attack with signals, pick candidate rails, choose a minimal config and test it on NeMo.", verb: "guardrail recommender",
      subs: [
        { key: "tag", label: "Tag signals", hint: "attack → signals", msg: "tagging signals…", render: signalsHTML },
        { key: "pool", label: "Candidate pool", hint: "65 rails → candidates", msg: "building candidate pool…", render: poolHTML },
        { key: "select", label: "Select minimal config", hint: "options + NeMo config", msg: "selecting minimal config…", render: selectHTML },
        { key: "test", label: "Test on NeMo /v1/checks", hint: "blocked / not blocked", msg: "testing on NeMo…", render: testHTML },
      ],
      summary: (c) => `${Data.blockedCount(c.uc)}/${Data.attacks(c.uc).length} blocked`,
    },
  ];
  const ctx = () => ({ uc: curUC(), a: curAttack() });
  const statusOf = (i) => (state.running === i ? "running" : i < state.done ? "completed" : "pending");
  const STATUS_LABEL = { pending: "Not started", running: "Running", completed: "Completed" };
  const revealed = (i) => (state.running === i ? state.sub : i < state.done ? STAGES[i].subs.length : 0);

  /* ---------- engine ---------- */
  const STEP_MS = 1200;
  function clearTimer() { if (state.timer) { clearTimeout(state.timer); state.timer = null; } }
  function startStage(i) {
    if (state.running !== -1 || i !== state.done || i >= STAGES.length) return;
    state.running = i; state.sub = 0; state.sel = i; state.tab[i] = 0;
    render();
    schedule();
  }
  function schedule() {
    clearTimer();
    if (state.paused || state.running < 0) return;
    state.timer = setTimeout(() => {
      const i = state.running;
      state.sub++;
      state.tab[i] = state.sub - 1;
      if (state.sub >= STAGES[i].subs.length) {
        state.running = -1; state.sub = 0; state.done = i + 1; state.tab[i] = 0;
        render();
        if (state.runAll && state.done < STAGES.length) state.timer = setTimeout(() => startStage(state.done), 500);
        else state.runAll = false;
        return;
      }
      render();
      schedule();
    }, STEP_MS);
  }
  function reset() {
    clearTimer();
    Object.assign(state, { done: 0, running: -1, sub: 0, sel: 0, tab: {}, attack: 0, runAll: false, paused: false, sfilter: "", sshown: 20, scn: null, risk: null });
    render();
  }

  /* ---------- DOM ---------- */
  const $ = (id) => document.getElementById(id);

  function renderCards() {
    const c = ctx();
    $("pipeline").innerHTML = STAGES.map((s, i) => {
      const st = statusOf(i);
      const nextable = st === "pending" && i === state.done && state.running === -1;
      const sum = st === "completed" ? s.summary(c) : "";
      return `<div class="stage-cell"><button type="button" class="stage ${state.sel === i ? "active" : ""}" data-act="sel" data-i="${i}" data-status="${st}" aria-pressed="${state.sel === i}"><span class="step">0${i + 1}</span><span class="stage-copy"><strong>${esc(s.name)}</strong><small>${esc(s.blurb)}</small><small class="stage-result">${esc(sum)}</small></span><span class="stage-state">${STATUS_LABEL[st]}</span></button>${nextable ? `<button type="button" class="secondary mini" data-act="run" data-i="${i}">Run</button>` : ""}</div>`;
    }).join("");
  }
  function renderControls() {
    const busy = state.running !== -1;
    const next = STAGES[state.done];
    const b = $("run-next");
    b.disabled = busy || !next;
    b.innerHTML = next ? `Run ${esc(next.verb)} <span aria-hidden="true">→</span>` : "All stages complete";
    $("run-all").disabled = busy || !next;
    $("reset").disabled = !busy && state.done === 0;
  }
  function renderProgress() {
    const el = $("progress");
    const i = state.running;
    if (i < 0) { el.hidden = true; return; }
    const s = STAGES[i];
    el.hidden = false;
    $("progress-text").textContent = `Running ${s.verb} — ${s.subs[Math.min(state.sub, s.subs.length - 1)].msg}`;
    $("progress-bar").style.width = Math.round((100 * (state.sub + 1)) / s.subs.length) + "%";
  }
  function emptyPanel(i) {
    const s = STAGES[i];
    const canRun = i === state.done && state.running === -1;
    const prev = i > 0 ? STAGES[state.done].name : "";
    return `<div class="empty"><span class="empty-number">0${i + 1}</span><h3>${esc(s.name)}</h3><p>${esc(s.desc)}</p><ul class="sublist">${s.subs.map((x) => `<li><b>${esc(x.label)}</b><span>${esc(x.hint)}</span></li>`).join("")}</ul>${canRun ? `<button type="button" class="secondary" data-act="run" data-i="${i}">Run ${esc(s.verb)}</button>` : `<p class="muted small">${state.running !== -1 ? "Waiting for the current stage to finish." : "Run " + esc(prev.toLowerCase()) + " first."}</p>`}</div>`;
  }
  function renderPanel() {
    const i = state.sel, s = STAGES[i];
    const st = statusOf(i), rev = revealed(i);
    $("panel-kicker").textContent = `0${i + 1} / ${s.name.toUpperCase()}`;
    $("panel-title").textContent = s.title;
    $("panel-description").textContent = s.desc;
    const badge = $("panel-badge");
    badge.textContent = STATUS_LABEL[st];
    badge.className = "badge " + (st === "completed" ? "pass" : "saved");
    const tabs = $("subtabs"), body = $("results");
    if (rev === 0) {
      tabs.hidden = true; tabs.innerHTML = "";
      body.innerHTML = emptyPanel(i);
      return;
    }
    const active = Math.min(state.tab[i] == null ? 0 : state.tab[i], rev - 1);
    tabs.hidden = false;
    tabs.innerHTML = s.subs.map((x, k) => {
      const ready = k < rev;
      const running = st === "running" && k === rev;
      return `<button type="button" role="tab" class="subtab ${k === active ? "on" : ""} ${ready ? "" : "wait"}" data-act="tab" data-i="${k}" aria-selected="${k === active}" ${ready ? "" : "disabled"}><span class="n">${k + 1}</span>${esc(x.label)}<small>${ready ? "done" : running ? "running…" : "waiting"}</small></button>`;
    }).join("");
    body.innerHTML = `<div class="results-inner" role="tabpanel">${s.subs[active].render(ctx())}</div>`;
  }
  function render() {
    if (typeof document === "undefined") return;
    const y = window.scrollY;
    renderCards(); renderControls(); renderProgress(); renderPanel();
    window.scrollTo(0, y);
  }

  function setTheme(dark) {
    document.documentElement.classList.toggle("pf-v6-theme-dark", dark);
    $("theme").textContent = dark ? "Light mode" : "Dark mode";
    try { localStorage.setItem("asago-theme", dark ? "dark" : "light"); } catch (e) { /* ignore */ }
  }

  function loadUC() {
    const uc = curUC();
    if (!uc) return;
    const sel = $("uc-select");
    $("ctx-policy").textContent = (uc.policy && uc.policy.name) || Data.prov(uc, "policy").source_doc || "n/a";
    $("ctx-models").textContent = [Data.prov(uc, "scenarios").model, Data.prov(uc, "recommender").tagger_model].filter(Boolean).filter((v, i, a) => a.indexOf(v) === i).join(" · ") || "n/a";
    $("ctx-system").textContent = uc.title;
    sel.value = String(state.uc);
    $("desc-title").textContent = uc.title;
    $("desc-body").textContent = uc.description || "";
  }

  function init() {
    const ucs = Data.useCases();
    $("uc-select").innerHTML = ucs.map((u, i) => `<option value="${i}">${esc(u.title)}</option>`).join("");
    const q = new URLSearchParams((typeof location !== "undefined" && location.search) || "");
    let saved = null; try { saved = localStorage.getItem("asago-theme"); } catch (e) { /* ignore */ }
    setTheme(q.get("theme") ? q.get("theme") !== "light" : saved !== "light");
    $("replay-label").textContent = `Replaying recorded run (${Data.replayDate()}) — no live inference`;
    $("footer-replay").textContent = $("replay-label").textContent;

    document.addEventListener("click", (e) => {
      const t = e.target.closest("[data-act]");
      if (!t) return;
      const act = t.dataset.act, i = +t.dataset.i;
      if (act === "sel") { state.sel = i; render(); }
      else if (act === "run") startStage(i);
      else if (act === "tab") { state.tab[state.sel] = i; render(); }
      else if (act === "attack") { state.attack = i; render(); }
      else if (act === "sfilter") { state.sfilter = state.sfilter === t.dataset.v ? "" : t.dataset.v; state.sshown = 20; render(); }
      else if (act === "more") { state.sshown += 40; render(); }
      else if (act === "risk") { state.risk = state.risk === t.dataset.id ? null : t.dataset.id; render(); }
      else if (act === "scn") { state.scn = state.scn === t.dataset.id ? null : t.dataset.id; render(); }
    });
    document.addEventListener("keydown", (e) => {
      if ((e.key === "Enter" || e.key === " ") && e.target.matches && e.target.matches("tr[data-act]")) { e.preventDefault(); e.target.click(); }
    });
    document.addEventListener("change", (e) => {
      if (e.target.id === "sf") { state.sfilter = e.target.value; state.sshown = 20; render(); }
      else if (e.target.id === "uc-select") { clearTimer(); state.uc = +e.target.value; reset(); loadUC(); render(); }
    });
    document.addEventListener("toggle", (e) => {
      const d = e.target;
      if (d && d.matches && d.matches("details.deep[data-k]")) { d.open ? state.open.add(d.dataset.k) : state.open.delete(d.dataset.k); }
    }, true);
    $("run-next").addEventListener("click", () => startStage(state.done));
    $("run-all").addEventListener("click", () => { if (state.running === -1 && state.done < STAGES.length) { state.runAll = true; startStage(state.done); } });
    $("reset").addEventListener("click", reset);
    $("theme").addEventListener("click", () => setTheme(!document.documentElement.classList.contains("pf-v6-theme-dark")));
    $("desc-open").addEventListener("click", () => { const d = $("desc-dialog"); if (d.showModal) d.showModal(); else d.setAttribute("open", ""); });
    $("desc-close").addEventListener("click", () => $("desc-dialog").close());

    // Deep link for screenshots: ?uc=1&done=2&running=3&sub=1&sel=3&tab=1&attack=2&open=grid,nemo1&theme=light
    const num = (k) => (q.get(k) != null && !isNaN(+q.get(k)) ? +q.get(k) : null);
    if (num("uc") != null && ucs[num("uc")]) state.uc = num("uc");
    if (num("attack") != null) state.attack = Math.max(0, Math.min(num("attack"), Data.attacks(curUC()).length - 1));
    if (num("done") != null) state.done = Math.max(0, Math.min(num("done"), STAGES.length));
    if (num("running") != null && num("running") >= 0 && num("running") < STAGES.length) {
      state.done = num("running"); state.running = num("running"); state.sub = Math.min(num("sub") || 0, STAGES[state.running].subs.length - 1); state.paused = true;
      state.tab[state.running] = Math.max(0, state.sub - 1);
    }
    state.sel = num("sel") != null ? Math.max(0, Math.min(num("sel"), 3)) : state.running >= 0 ? state.running : Math.max(0, Math.min(state.done, 3) - (state.done >= STAGES.length ? 1 : 0));
    if (num("tab") != null) state.tab[state.sel] = num("tab");
    (q.get("open") || "").split(",").filter(Boolean).forEach((k) => state.open.add(k));
    loadUC();
    render();
    if (q.get("autorun") === "all") { state.runAll = true; startStage(0); }
  }

  if (typeof document !== "undefined" && document.getElementById("pipeline")) {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init); else init();
  }
  if (typeof module !== "undefined") module.exports = { Data, STAGES, state, ctx, esc, conversationHTML, baselineHTML, testHTML, startStage, reset, statusOf };
})();
