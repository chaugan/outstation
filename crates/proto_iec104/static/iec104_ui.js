// IEC 60870-5-104 slave-detail UI renderer.
//
// Concatenated into `crates/webui/src/index.html` at build time by
// `crates/webui/build.rs`. Registers its entry points on
// `window.PROTOCOL_RENDERERS['iec104']`; the core `renderSlaveDetail`
// dispatcher looks up the right renderer based on the report's
// `protocol` field.
//
// All protocol-specific data is read from `detail.protocol_specific`,
// which for IEC 104 is `{ playback, target, timing, cp56_drift }`.
// The core analyzer keeps `detail.protocol_specific` canonical; this
// file is the only place in the served page that knows those keys.

(function () {
  // IEC 104 ASDU type-ID short names. Keep in sync with
  // crates/proto_iec104/src/asdu.rs ELEMENT_LEN. Only the common
  // types are listed; unknown IDs render as the raw number.
  const IEC104_TYPE_NAMES = {
    1:'M_SP_NA_1', 2:'M_SP_TA_1', 3:'M_DP_NA_1', 4:'M_DP_TA_1',
    5:'M_ST_NA_1', 6:'M_ST_TA_1', 7:'M_BO_NA_1', 8:'M_BO_TA_1',
    9:'M_ME_NA_1', 10:'M_ME_TA_1', 11:'M_ME_NB_1', 12:'M_ME_TB_1',
    13:'M_ME_NC_1', 14:'M_ME_TC_1', 15:'M_IT_NA_1', 16:'M_IT_TA_1',
    30:'M_SP_TB_1', 31:'M_DP_TB_1', 32:'M_ST_TB_1', 33:'M_BO_TB_1',
    34:'M_ME_TD_1', 35:'M_ME_TE_1', 36:'M_ME_TF_1', 37:'M_IT_TB_1',
    45:'C_SC_NA_1', 46:'C_DC_NA_1', 47:'C_RC_NA_1', 48:'C_SE_NA_1',
    49:'C_SE_NB_1', 50:'C_SE_NC_1', 51:'C_BO_NA_1',
    58:'C_SC_TA_1', 59:'C_DC_TA_1', 60:'C_RC_TA_1', 61:'C_SE_TA_1',
    62:'C_SE_TB_1', 63:'C_SE_TC_1', 64:'C_BO_TA_1',
    70:'M_EI_NA_1', 100:'C_IC_NA_1', 101:'C_CI_NA_1', 102:'C_RD_NA_1',
    103:'C_CS_NA_1', 104:'C_TS_NA_1', 105:'C_RP_NA_1', 106:'C_CD_NA_1',
    107:'C_TS_TA_1',
  };

  function tidName(t) {
    return IEC104_TYPE_NAMES[t] || `type ${t}`;
  }

  function tidHist(ids) {
    const m = new Map();
    for (const t of ids) m.set(t, (m.get(t) || 0) + 1);
    return [...m.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0]);
  }

  // Side-by-side ASDU type histogram. Per-type delta (captured − expected)
  // is shown so divergence is obvious at a glance even for thousand-frame pcaps.
  function renderTidHistogram(expected, captured) {
    const e = new Map(tidHist(expected));
    const c = new Map(tidHist(captured));
    const allTids = new Set([...e.keys(), ...c.keys()]);
    const rows = [...allTids].sort((a, b) => (c.get(b) || e.get(b) || 0) - (c.get(a) || e.get(a) || 0) || a - b);
    let h = `<div class="an-tid-hist">`;
    h += `<div class="hd">EXPECTED (${expected.length} frames)</div>`;
    h += `<div class="hd">CAPTURED (${captured.length} frames)</div>`;
    for (const t of rows) {
      const ec = e.get(t) || 0;
      const cc = c.get(t) || 0;
      const d  = cc - ec;
      const dStr = d === 0 ? '' : `<span class="delta ${d>0?'ok':''}">${d>0?'+':''}${d}</span>`;
      h += `<div class="row"><span class="nm">${esc(tidName(t))} <span class="ct">[${t}]</span></span><span class="ct">${ec}</span></div>`;
      h += `<div class="row"><span class="nm">${esc(tidName(t))} <span class="ct">[${t}]</span></span><span class="ct">${cc}</span>${dStr}</div>`;
    }
    h += `</div>`;
    return h;
  }

  // Collapsible full-sequence dump for byte-for-byte inspection.
  // Default closed; truncated past 2000 IDs to keep the DOM lean.
  function renderTidSequenceCollapsible(label, ids) {
    if (!ids.length) return '';
    const MAX_DUMP = 2000;
    const head = ids.length <= MAX_DUMP
      ? ids.join(' ')
      : ids.slice(0, MAX_DUMP).join(' ') + ` … (truncated, ${ids.length - MAX_DUMP} more)`;
    return `<details class="an-seq"><summary>show full ${esc(label)} sequence (${ids.length})</summary><div class="an-tid-seq">${head}</div></details>`;
  }

  // CP56-drift scatter: every per-frame signed drift with the
  // ±tolerance corridor as a faint band so outliers stand out.
  function renderDriftScatter(containerId, drift) {
    const node = el(containerId);
    if (!node || !drift || !drift.drift_samples_ms || !drift.drift_samples_ms.length) return;
    const tol = drift.tolerance_ms || 50;
    const okColor  = getCssVar('--ok')  || '#3f6430';
    const errColor = getCssVar('--err') || '#922626';
    const dimColor = getCssVar('--dim') || '#857f70';
    const inP  = [];
    const outP = [];
    const idxs = drift.sample_frame_indices || [];
    const tids = drift.sample_type_ids || [];
    for (let i = 0; i < drift.drift_samples_ms.length; i++) {
      const x = idxs[i] != null ? idxs[i] : i;
      const y = drift.drift_samples_ms[i];
      const ent = [x, y, tids[i] || 0];
      if (Math.abs(y) <= tol) inP.push(ent); else outP.push(ent);
    }
    const c = echarts.init(node, null, { renderer: 'canvas' });
    c.setOption({
      backgroundColor: 'transparent',
      animation: false,
      grid: { left: 56, right: 14, top: 28, bottom: 56 },
      toolbox: {
        right: 14, top: 2,
        feature: {
          dataZoom: { yAxisIndex: 'none', title: { zoom: 'zoom (drag a rectangle)', back: 'reset zoom' } },
          restore: { title: 'reset' },
        },
        iconStyle: { borderColor: dimColor },
      },
      tooltip: {
        trigger: 'item',
        formatter: (p) => {
          const tid = (p.value && p.value[2]) || 0;
          return `frame #${p.value[0]}<br>${tidName(tid)} [${tid}]<br>drift: ${p.value[1].toFixed(2)} ms`;
        },
      },
      xAxis: { type: 'value',
               axisLine: { lineStyle: { color: dimColor } }, axisLabel: { color: dimColor, fontSize: 10 },
               splitLine: { show: false } },
      yAxis: { type: 'value',
               axisLine: { lineStyle: { color: dimColor } }, axisLabel: { color: dimColor, fontSize: 10, formatter: '{value} ms' },
               splitLine: { lineStyle: { color: 'rgba(0,0,0,0.06)' } } },
      dataZoom: [
        { type: 'inside', xAxisIndex: 0 },
        { type: 'slider', xAxisIndex: 0, height: 16, bottom: 8, borderColor: 'transparent',
          textStyle: { color: dimColor, fontSize: 9 } },
      ],
      series: [
        { name: 'in tolerance', type: 'scatter', data: inP, symbolSize: 4,
          large: true, largeThreshold: 1500, itemStyle: { color: okColor },
          markArea: {
            silent: true,
            itemStyle: { color: 'rgba(63,100,48,0.07)' },
            data: [[{ yAxis: -tol }, { yAxis: tol }]],
          },
        },
        { name: 'out of tolerance', type: 'scatter', data: outP, symbolSize: 6,
          large: true, largeThreshold: 1500, itemStyle: { color: errColor } },
      ],
    });
    trackAnalysisChart(c);
  }

  // Inter-frame gap timing: original (muted) vs captured (accent).
  function renderGapComparison(containerId, timing) {
    const node = el(containerId);
    if (!node || !timing) return;
    const orig = timing.original_gaps_ms || [];
    const cap  = timing.captured_gaps_ms || [];
    if (!orig.length && !cap.length) return;
    const accColor = getCssVar('--accent') || '#b8441a';
    const dimColor = getCssVar('--dim')    || '#857f70';
    const inkColor = getCssVar('--ink-2')  || '#5a5750';
    const c = echarts.init(node, null, { renderer: 'canvas' });
    c.setOption({
      backgroundColor: 'transparent',
      animation: false,
      grid: { left: 64, right: 14, top: 32, bottom: 56 },
      toolbox: {
        right: 110, top: 2,
        feature: {
          dataZoom: { yAxisIndex: 'none', title: { zoom: 'zoom (drag a rectangle)', back: 'reset zoom' } },
          restore: { title: 'reset' },
        },
        iconStyle: { borderColor: dimColor },
      },
      legend: { data: ['original', 'captured'], textStyle: { color: dimColor, fontSize: 10 }, top: 4, right: 12 },
      tooltip: {
        trigger: 'axis',
        formatter: (params) => {
          if (!params || !params.length) return '';
          const idx = params[0].axisValue;
          let s = `gap #${idx}<br>`;
          for (const p of params) s += `${p.marker} ${p.seriesName}: ${Number(p.value).toFixed(2)} ms<br>`;
          return s;
        },
      },
      xAxis: { type: 'category',
               data: Array.from({ length: Math.max(orig.length, cap.length) }, (_, i) => String(i + 1)),
               axisLine: { lineStyle: { color: dimColor } }, axisLabel: { color: dimColor, fontSize: 10 } },
      yAxis: { type: 'value',
               axisLine: { lineStyle: { color: dimColor } }, axisLabel: { color: dimColor, fontSize: 10, formatter: '{value} ms' },
               splitLine: { lineStyle: { color: 'rgba(0,0,0,0.06)' } } },
      dataZoom: [
        { type: 'inside', xAxisIndex: 0 },
        { type: 'slider', xAxisIndex: 0, height: 16, bottom: 8, borderColor: 'transparent',
          textStyle: { color: dimColor, fontSize: 9 } },
      ],
      series: [
        { name: 'original', type: 'line', data: orig, showSymbol: false, smooth: false,
          lineStyle: { color: inkColor, width: 1, type: 'dashed' },
          areaStyle: { color: 'rgba(90,87,80,0.08)' }, sampling: 'lttb' },
        { name: 'captured', type: 'line', data: cap, showSymbol: false, smooth: false,
          lineStyle: { color: accColor, width: 1.4 }, sampling: 'lttb' },
      ],
    });
    trackAnalysisChart(c);
  }

  // |drift| histogram. Bars under the tolerance threshold are green,
  // above are red — visual cliff at the threshold.
  function renderDriftHistogram(containerId, drift) {
    const node = el(containerId);
    if (!node || !drift || !drift.drift_samples_ms || !drift.drift_samples_ms.length) return;
    const tol = drift.tolerance_ms || 50;
    const okColor  = getCssVar('--ok')  || '#3f6430';
    const errColor = getCssVar('--err') || '#922626';
    const dimColor = getCssVar('--dim') || '#857f70';
    const abs = drift.drift_samples_ms.map(Math.abs);
    const max = Math.max(...abs, tol * 1.5);
    const targetBins = 30;
    let step = Math.max(1, Math.ceil(max / targetBins));
    const mag = Math.pow(10, Math.floor(Math.log10(step)));
    const norm = step / mag;
    step = (norm <= 1 ? 1 : norm <= 2 ? 2 : norm <= 5 ? 5 : 10) * mag;
    const binCount = Math.ceil(max / step) + 1;
    const counts = new Array(binCount).fill(0);
    for (const v of abs) {
      const b = Math.min(binCount - 1, Math.floor(v / step));
      counts[b] += 1;
    }
    const labels = counts.map((_, i) => `${(i * step).toFixed(0)}–${((i + 1) * step).toFixed(0)}`);
    const bars = counts.map((ct, i) => {
      const lo = i * step;
      return { value: ct, itemStyle: { color: lo + step <= tol ? okColor : errColor } };
    });
    const c = echarts.init(node, null, { renderer: 'canvas' });
    const rotate = labels.length > 8;
    c.setOption({
      backgroundColor: 'transparent',
      animation: false,
      grid: { left: 52, right: 14, top: 14, bottom: rotate ? 48 : 28 },
      tooltip: { trigger: 'axis', axisPointer: { type: 'shadow' },
        formatter: (p) => `|drift| ${labels[p[0].dataIndex]} ms<br>${p[0].value} samples` },
      xAxis: { type: 'category',
               data: labels, axisLine: { lineStyle: { color: dimColor } },
               axisTick: { alignWithLabel: true },
               axisLabel: { color: dimColor, fontSize: 9, rotate: rotate ? 40 : 0, interval: 0, margin: 8 } },
      yAxis: { type: 'value',
               axisLine: { lineStyle: { color: dimColor } }, axisLabel: { color: dimColor, fontSize: 10 },
               splitLine: { lineStyle: { color: 'rgba(0,0,0,0.06)' } } },
      series: [{
        type: 'bar', data: bars, barCategoryGap: '20%',
        markLine: { silent: true, symbol: 'none',
          data: [{ xAxis: Math.floor(tol / step) - 0.5, label: { formatter: `${tol} ms tolerance`, color: dimColor, fontSize: 9 },
                   lineStyle: { color: dimColor, type: 'dashed' } }] },
      }],
    });
    trackAnalysisChart(c);
  }

  // Top-N anomaly callout list. Plain HTML — no chart.
  function renderTopAnomalies(containerId, drift, topN) {
    const node = el(containerId);
    if (!node || !drift || !drift.drift_samples_ms) return;
    topN = topN || 10;
    const tol = drift.tolerance_ms || 50;
    const idxs = drift.sample_frame_indices || [];
    const tids = drift.sample_type_ids || [];
    const ranked = drift.drift_samples_ms
      .map((d, i) => ({ d, i, idx: idxs[i] != null ? idxs[i] : i, tid: tids[i] || 0 }))
      .sort((a, b) => Math.abs(b.d) - Math.abs(a.d))
      .slice(0, topN);
    let h = '';
    if (drift.out_of_tolerance === 0) {
      h += `<div class="empty">no CP56 stamps outside ±${tol.toFixed(0)} ms — every event landed within tolerance</div>`;
    }
    for (const r of ranked) {
      const sign = r.d >= 0 ? '+' : '';
      const driftCls = Math.abs(r.d) <= tol ? 'drift ok' : 'drift';
      const ctx = Math.abs(r.d) <= tol ? `within tolerance` : `exceeds ${tol.toFixed(0)} ms`;
      h += `<div class="row">`;
      h += `  <div class="idx">#${r.idx}</div>`;
      h += `  <div class="name">${esc(tidName(r.tid))} <span style="color:var(--dim);font-size:10px">[${r.tid}]</span></div>`;
      h += `  <div class="${driftCls}">${sign}${r.d.toFixed(1)} ms</div>`;
      h += `  <div class="ctx">${esc(ctx)}</div>`;
      h += `</div>`;
    }
    if (drift.samples_truncated) {
      h += `<div class="ctx" style="margin-top:6px">note: per-frame samples were capped at the analyzer's safety limit; aggregate stats above remain accurate.</div>`;
    }
    node.innerHTML = h;
  }

  // Entry point #1 — per-slave drill-down HTML. Mirrors the pre-refactor
  // in-core renderer: the HTML structure is identical, only the data
  // source moved from `d.{playback,target,timing,cp56_drift}` (flattened
  // shortcuts) to the canonical `d.protocol_specific.*`.
  function renderSlaveDetail(slaveIp, d) {
    const slug = slaveSlug(slaveIp);
    const ps = d.protocol_specific || {};
    const pb = ps.playback;
    const tg = ps.target;
    const t  = ps.timing;
    const cp = ps.cp56_drift;
    let h = ``;
    if (d.tcp_flow) {
      h += `<div class="an-kv">`;
      h += `<div class="k">tcp flow</div><div class="v">${esc(d.tcp_flow.client)} → ${esc(d.tcp_flow.server)} · ${d.tcp_flow.packets} pkts · <code>${esc(d.tcp_flow.state || 'no state')}</code></div>`;
      h += `</div>`;
    }

    if (pb) {
      h += `<div class="an-h">PLAYBACK SIDE (${esc(pb.direction)})</div>`;
      h += `<div class="an-kv">`;
      h += `<div class="k">expected i-frames</div><div class="v">${pb.expected_iframes}</div>`;
      const delivOk = pb.delivered_iframes === pb.expected_iframes;
      h += `<div class="k">delivered</div><div class="v ${delivOk?'ok':'bad'}">${pb.delivered_iframes}</div>`;
      h += `<div class="k">type-id sequence</div><div class="v ${pb.type_id_sequence_match?'ok':'warn'}">${pb.type_id_sequence_match ? 'match' : 'divergent'} · ${pb.matched_type_ids}/${pb.expected_iframes} matched</div>`;
      const cp56Only = pb.cp56_only_count || 0;
      const realMm = (pb.real_mismatch_count != null) ? pb.real_mismatch_count : pb.mismatches.length;
      const allOk = (pb.byte_identical_count + cp56Only) === pb.expected_iframes && realMm === 0;
      const parts = [];
      parts.push(`<span class="ok">${pb.byte_identical_count} byte-identical</span>`);
      if (cp56Only > 0) {
        parts.push(`<span class="ok" title="Same data, only the embedded CP56Time2a timestamp differs — exactly what fresh-timestamps mode does. Counts as a successful frame, not a mismatch.">${cp56Only} CP56-only \u2713</span>`);
      }
      if (realMm > 0) {
        parts.push(`<span class="bad">${realMm} real mismatch${realMm===1?'':'es'}</span>`);
      } else {
        parts.push(`<span class="ok">0 real mismatches</span>`);
      }
      const bdLine = `${pb.expected_iframes} frames &middot; ${parts.join(' &middot; ')}`;
      h += `<div class="k">body diff</div><div class="v ${allOk?'ok':(realMm>0?'bad':'')}">${bdLine}</div>`;
      if (pb.missing_indices.length) {
        h += `<div class="k">missing idx</div><div class="v bad">${pb.missing_indices.slice(0,20).join(', ')}${pb.missing_indices.length>20?'…':''}</div>`;
      }
      h += `</div>`;
      h += renderTidHistogram(pb.expected_type_ids, pb.delivered_type_ids);
      h += renderTidSequenceCollapsible('expected', pb.expected_type_ids);
      h += renderTidSequenceCollapsible('captured', pb.delivered_type_ids);
      if (pb.mismatches.length) {
        h += `<div class="an-h">REAL MISMATCHES (${pb.mismatches.length})</div>`;
        h += `<div class="muted" style="font-family:var(--mono);font-size:11px;margin:-6px 0 8px">CP56-only diffs (timestamps we deliberately rewrote) are excluded — they're tallied above.</div>`;
        for (const m of pb.mismatches.slice(0, 20)) {
          h += `<div class="an-diff-row">`;
          h += `  <div><span class="lbl">idx</span> ${m.index} · exp tid=${m.expected_type_id} · got tid=${m.actual_type_id}</div>`;
          h += `  <div><span class="lbl">exp asdu</span> ${esc(m.expected_asdu_hex)}</div>`;
          h += `  <div><span class="lbl">got asdu</span> ${esc(m.actual_asdu_hex)}</div>`;
          h += `</div>`;
        }
      }
    }

    if (tg) {
      h += `<div class="an-h">TARGET SIDE (${esc(tg.direction)})</div>`;
      h += `<div class="an-kv">`;
      h += `<div class="k">u / s / i frames</div><div class="v">${tg.u_frames} · ${tg.s_frames} · ${tg.i_frames}</div>`;
      h += `<div class="k">u-codes seen</div><div class="v">${tg.u_codes_seen.map(esc).join(', ') || '—'}</div>`;
      h += `<div class="k">startdt handshake</div><div class="v ${tg.startdt_handshake_ok?'ok':'bad'}">${tg.startdt_handshake_ok ? 'completed' : 'missing'}</div>`;
      h += `</div>`;
      if (tg.target_type_ids.length) {
        h += `<div class="muted" style="font-family:var(--sans);font-size:10px;text-transform:uppercase;letter-spacing:0.06em;color:var(--dim);margin-top:8px">target's I-frame types</div>`;
        const hist = tidHist(tg.target_type_ids);
        h += `<div class="an-tid-hist" style="grid-template-columns:1fr">`;
        h += `<div class="hd">${tg.target_type_ids.length} frames sent by target</div>`;
        for (const [tid, ct] of hist) {
          h += `<div class="row"><span class="nm">${esc(tidName(tid))} <span class="ct">[${tid}]</span></span><span class="ct">${ct}</span></div>`;
        }
        h += `</div>`;
        h += renderTidSequenceCollapsible('target', tg.target_type_ids);
      }

      if (tg.correctness) {
        const c = tg.correctness;
        const kindLabel = {
          same_script: 'TARGET REPLAYED THE ORIGINAL SCRIPT',
          subset: 'TARGET REPLAYED A SUBSET OF THE SCRIPT',
          divergent: 'TARGET RAN ITS OWN SCRIPT',
          silent: 'TARGET SENT NO I-FRAMES',
        }[c.target_script_kind] || c.target_script_kind.toUpperCase();
        const kindColor = {
          same_script: 'var(--ok)',
          subset: 'var(--blue)',
          divergent: 'var(--blue)',
          silent: 'var(--warn)',
        }[c.target_script_kind] || 'var(--dim)';
        const kindHelp = {
          same_script: "the live target produced the same iec 104 command sequence as the captured master. if the target is a separate piece of software, this is a strong positive signal.",
          subset: "the live target produced a prefix/subset of the captured script. probably a truncated run or a simpler master that only issues a few commands.",
          divergent: "the live target is running a different command script than the captured master. this is normal when the live master is a different piece of software — it's not an error, just a different peer. the delivery side of the replay is still judged separately.",
          silent: "the live target never sent any i-frames of its own. it handshook and ack'd, but it didn't issue any commands. expected for a purely passive master or when the session was cut short.",
        }[c.target_script_kind] || '';

        h += `<div class="an-h">TARGET SCRIPT COMPARISON (correct mode)</div>`;
        h += `<div style="padding:10px 12px;background:var(--surface-2);border:1px solid var(--rule);border-left:2px solid ${kindColor};margin:6px 0 10px">`;
        h += `  <div style="font-family:var(--sans);font-size:10px;font-weight:700;letter-spacing:0.1em;color:${kindColor};margin-bottom:6px">${esc(kindLabel)}</div>`;
        h += `  <div style="font-family:var(--mono);font-size:11px;color:var(--ink-2);line-height:1.5">${esc(kindHelp)}</div>`;
        h += `</div>`;
        h += `<div class="an-kv">`;
        h += `<div class="k">original sent</div><div class="v">${c.expected_iframes} i-frames</div>`;
        h += `<div class="k">target sent</div><div class="v">${c.actual_iframes} i-frames</div>`;
        h += `<div class="k">type-id overlap</div><div class="v">${c.lcs_type_ids}/${c.expected_iframes} &middot; ${(c.lcs_similarity*100).toFixed(0)}% similarity (lcs)</div>`;
        const cCp56Only = c.cp56_only_count || 0;
        const cParts = [`<span class="ok">${c.byte_identical_count} byte-identical</span>`];
        if (cCp56Only > 0) {
          cParts.push(`<span class="ok" title="Target's reply differs from the original only in CP56Time2a — common when the live target generates its own timestamps from its own clock.">${cCp56Only} CP56-only \u2713</span>`);
        }
        if (c.total_mismatches > 0) {
          cParts.push(`<span class="bad">${c.total_mismatches} real diff${c.total_mismatches===1?'':'s'}</span>`);
        } else {
          cParts.push(`<span class="ok">0 real diffs</span>`);
        }
        h += `<div class="k">body diff</div><div class="v">${c.expected_iframes} frames &middot; ${cParts.join(' &middot; ')}</div>`;
        h += `<div class="k">matched prefix</div><div class="v">${c.matched_type_id_prefix}/${c.expected_iframes} (index-by-index)</div>`;
        h += `</div>`;
        h += renderTidHistogram(c.original_type_ids || [], tg.target_type_ids);
        h += renderTidSequenceCollapsible('original target', c.original_type_ids || []);
        h += renderTidSequenceCollapsible('live target', tg.target_type_ids);
      }
    }

    if (t) {
      h += `<div class="an-h">TIMING</div>`;
      h += `<div class="an-kv">`;
      h += `<div class="k">duration (original)</div><div class="v">${(t.original_duration_ms/1000).toFixed(3)} s</div>`;
      h += `<div class="k">duration (captured)</div><div class="v">${(t.captured_duration_ms/1000).toFixed(3)} s</div>`;
      if (t.speedup_factor > 0) {
        const sp = t.speedup_factor;
        const label = sp > 2 ? `${sp.toFixed(1)}× faster (fast mode)` : sp > 0.5 ? `~matched (original pacing)` : `${(1/sp).toFixed(1)}× slower`;
        h += `<div class="k">speedup</div><div class="v">${esc(label)}</div>`;
      }
      h += `<div class="k">mean gap</div><div class="v">orig ${t.original_mean_gap_ms.toFixed(1)} ms · capt ${t.captured_mean_gap_ms.toFixed(2)} ms</div>`;
      h += `<div class="k">p50 gap</div><div class="v">orig ${t.original_p50_gap_ms.toFixed(1)} ms · capt ${t.captured_p50_gap_ms.toFixed(2)} ms</div>`;
      h += `<div class="k">p99 gap</div><div class="v">orig ${t.original_p99_gap_ms.toFixed(1)} ms · capt ${t.captured_p99_gap_ms.toFixed(2)} ms</div>`;
      h += `</div>`;
    }

    // Anomaly charts — CP56 drift scatter + histogram + top-10, and
    // inter-frame gap comparison. Placeholders; filled by initSlaveCharts.
    const haveDriftSamples = cp && (cp.drift_samples_ms || []).length > 0;
    const haveGapData = t && ((t.original_gaps_ms || []).length > 0
                           || (t.captured_gaps_ms || []).length > 0);
    if (haveDriftSamples || haveGapData) {
      h += `<div class="an-h">ANOMALY DETECTION</div>`;
      h += `<div class="muted" style="font-family:var(--mono);font-size:10px;margin-bottom:6px">scroll inside a chart to zoom &middot; drag to pan &middot; use the toolbox icons (top-right) for rectangular zoom or reset</div>`;
      if (haveDriftSamples) {
        h += `<div class="an-chart-caption">CP56 drift over time &middot; every event vs. wire send moment (band = ±tolerance)</div>`;
        h += `<div class="an-chart-axes">X: frame index &middot; Y: drift (ms, signed)</div>`;
        h += `<div id="an-chart-drift-${slug}" class="an-chart"></div>`;
      }
      if (haveGapData) {
        h += `<div class="an-chart-caption">inter-frame gap timing &middot; original (dashed) vs. captured (solid)</div>`;
        h += `<div class="an-chart-axes">X: inter-frame gap index &middot; Y: gap duration (ms)</div>`;
        h += `<div id="an-chart-gap-${slug}" class="an-chart"></div>`;
      }
      if (haveDriftSamples) {
        h += `<div class="an-chart-caption">drift distribution &middot; bars beyond the dashed line are out-of-tolerance</div>`;
        h += `<div class="an-chart-axes">X: |drift| bucket (ms) &middot; Y: sample count</div>`;
        h += `<div id="an-chart-hist-${slug}" class="an-chart"></div>`;
        h += `<div class="an-chart-caption">worst CP56 drifts (top 10)</div>`;
        h += `<div id="an-anomalies-${slug}" class="an-anomaly-list"></div>`;
      }
    }

    if (cp) {
      const passed = cp.out_of_tolerance === 0;
      const withinPct = cp.samples > 0
        ? (100 * (cp.samples - cp.out_of_tolerance) / cp.samples).toFixed(2)
        : '0.00';
      h += `<div class="an-h">EMBEDDED TIMESTAMP ACCURACY <span class="opt">(fresh-timestamps mode)</span></div>`;
      h += `<div class="an-kv">`;
      h += `<div class="k">verdict</div><div class="v" style="color:${passed ? 'var(--ok,#6a0)' : 'var(--err,#c33)'}">` +
           `${withinPct}% of ${cp.samples} CP56Time2a fields within ±${cp.tolerance_ms.toFixed(0)} ms of wire time</div>`;
      h += `<div class="k">frames with CP56</div><div class="v">${cp.iframes_with_cp56}</div>`;
      h += `<div class="k">mean drift</div><div class="v">${cp.mean_ms.toFixed(2)} ms (signed ${cp.mean_signed_ms.toFixed(2)})</div>`;
      h += `<div class="k">p50 / p99 / max</div><div class="v">${cp.p50_ms.toFixed(2)} / ${cp.p99_ms.toFixed(2)} / ${cp.max_ms.toFixed(2)} ms</div>`;
      if (cp.out_of_tolerance > 0) {
        h += `<div class="k">out of tolerance</div><div class="v" style="color:var(--err,#c33)">${cp.out_of_tolerance} / ${cp.samples}</div>`;
      }
      if (cp.invalid_flag_count > 0 || cp.summer_flag_count > 0) {
        h += `<div class="k">flags observed</div><div class="v">IV=${cp.invalid_flag_count} · SU=${cp.summer_flag_count}</div>`;
      }
      h += `</div>`;
    }

    if (d.notes && d.notes.length) {
      h += `<div class="an-h">NOTES</div>`;
      for (const n of d.notes) h += `<div class="an-note">· ${esc(n)}</div>`;
    }

    return h;
  }

  // Entry point #2 — called after the slave row expands and the HTML
  // from `renderSlaveDetail` is mounted. Wires up the anomaly charts
  // that need a real DOM node to initialize.
  function initSlaveCharts(slug, d) {
    const ps = d.protocol_specific || {};
    const cp = ps.cp56_drift;
    const t  = ps.timing;
    if (cp && (cp.drift_samples_ms || []).length > 0) {
      renderDriftScatter('an-chart-drift-' + slug, cp);
      renderDriftHistogram('an-chart-hist-' + slug, cp);
      renderTopAnomalies('an-anomalies-' + slug, cp, 10);
    }
    if (t && ((t.original_gaps_ms || []).length > 0
           || (t.captured_gaps_ms || []).length > 0)) {
      renderGapComparison('an-chart-gap-' + slug, t);
    }
  }

  window.PROTOCOL_RENDERERS = window.PROTOCOL_RENDERERS || {};
  window.PROTOCOL_RENDERERS['iec104'] = { renderSlaveDetail, initSlaveCharts };
})();
