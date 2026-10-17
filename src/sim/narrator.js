// Narrates a simulation to the terminal and builds a Markdown report.
// expect() records assertions so a run doubles as an integration test.

export function createNarrator({ color = process.stdout.isTTY && !process.env.NO_COLOR, quiet = false } = {}) {
  const c = (code) => (s) => (color ? `\x1b[${code}m${s}\x1b[0m` : String(s));
  const bold = c('1'), dim = c('2'), green = c('32'), red = c('31'), yellow = c('33'), blue = c('34'), cyan = c('36');
  const out = (s = '') => {
    if (!quiet) console.log(s);
  };
  const md = [];
  const results = [];
  let current = null;
  let stepNo = 0;

  const decisionColor = (d) => (d === 'allow' ? green : d === 'deferred' || d === 'step_up' ? yellow : red);

  const n = {
    scenario(id, title, framing) {
      if (current) current.ended = Date.now();
      current = { id, title, assertions: [], started: Date.now() };
      results.push(current);
      stepNo = 0;
      out('');
      out(bold(cyan('═'.repeat(78))));
      out(bold(cyan(` ${title}`)));
      out(bold(cyan('═'.repeat(78))));
      if (framing) out(dim(wrap(framing, 78)));
      md.push(`\n## ${title}\n`, framing ? `${framing}\n` : '');
    },

    step(text) {
      stepNo += 1;
      out('');
      out(bold(`${stepNo}. ${text}`));
      md.push(`\n### ${stepNo}. ${text}\n`);
    },

    say(text) {
      out(wrap(text, 78, '   '));
      md.push(`${text}\n`);
    },

    act(actor, text) {
      out(`   ${blue('▸')} ${bold(actor)}: ${text}`);
      md.push(`- **${actor}**: ${text}`);
    },

    detail(label, value) {
      const v = typeof value === 'string' ? value : JSON.stringify(value);
      out(`     ${dim(label + ':')} ${v}`);
      md.push(`  - ${label}: \`${v}\``);
    },

    checks(list) {
      for (const ch of list) {
        out(`     ${ch.ok ? green('✓') : red('✗')} ${ch.name}${ch.detail ? dim(` (${ch.detail})`) : ''}`);
        md.push(`  - ${ch.ok ? '✓' : '✗'} ${ch.name}${ch.detail ? ` (${ch.detail})` : ''}`);
      }
    },

    decision(rpName, res) {
      const label = String(res.decision).toUpperCase();
      const why = res.reasons?.length ? ` — ${res.reasons.join('; ')}` : '';
      out(`   ${decisionColor(res.decision)('●')} ${bold(rpName)} → ${decisionColor(res.decision)(bold(label))} ${dim(`[${res.classification}${res.tier ? `, tier: ${res.tier}` : ''}]`)}${why}`);
      md.push(`- **${rpName} → ${label}** \`${res.classification}\`${res.tier ? ` (tier: ${res.tier})` : ''}${why}`);
    },

    learned(party, items) {
      out(`   ${cyan('◆')} ${bold(`What ${party} learned`)}`);
      md.push(`- *What ${party} learned:*`);
      for (const it of items) {
        out(`     ${dim('·')} ${it}`);
        md.push(`  - ${it}`);
      }
    },

    note(text) {
      out(dim(wrap(text, 78, '   ')));
      md.push(`> ${text}\n`);
    },

    table(headers, rows) {
      const widths = headers.map((h, i) => Math.max(h.length, ...rows.map((r) => String(r[i]).length)));
      const line = (cells) => '   ' + cells.map((cell, i) => String(cell).padEnd(widths[i])).join('  ');
      out(bold(line(headers)));
      out(dim('   ' + widths.map((w) => '─'.repeat(w)).join('  ')));
      for (const r of rows) out(line(r));
      md.push('', `| ${headers.join(' | ')} |`, `| ${headers.map(() => '---').join(' | ')} |`, ...rows.map((r) => `| ${r.join(' | ')} |`), '');
    },

    expect(condition, description) {
      const ok = Boolean(condition);
      current.assertions.push({ ok, description });
      out(`   ${ok ? green('✔ expected:') : red(bold('✘ UNEXPECTED:'))} ${ok ? dim(description) : description}`);
      md.push(`- ${ok ? '✔' : '✘ **UNEXPECTED**'} ${description}`);
      return ok;
    },

    error(err) {
      current?.assertions.push({ ok: false, description: `scenario crashed: ${err.message}` });
      out(red(`   ✘ scenario crashed: ${err.stack ?? err.message}`));
      md.push(`- ✘ **scenario crashed**: ${err.message}`);
    },

    summary() {
      out('');
      out(bold('Summary'));
      const rows = results.map((r) => {
        const passed = r.assertions.filter((a) => a.ok).length;
        return [r.title, `${passed}/${r.assertions.length}`, passed === r.assertions.length ? 'pass' : 'FAIL', `${(r.ended ?? Date.now()) - r.started}ms`];
      });
      n.table(['scenario', 'expectations', 'result', 'time'], rows);
      const ok = results.every((r) => r.assertions.every((a) => a.ok));
      out(ok ? green(bold('\nAll expectations met.')) : red(bold('\nSome expectations were not met.')));
      return ok;
    },

    get results() {
      return results;
    },

    markdown(title) {
      return `# ${title}\n\nGenerated ${new Date().toISOString()} by \`npm run sim\`.\n${md.join('\n')}\n`;
    },
  };
  return n;
}

function wrap(text, width, indent = '') {
  const words = String(text).split(/\s+/);
  const lines = [];
  let line = indent;
  for (const w of words) {
    if (line.length + w.length + 1 > width && line.trim()) {
      lines.push(line);
      line = indent;
    }
    line += (line.trim() ? ' ' : '') + w;
  }
  if (line.trim()) lines.push(line);
  return lines.join('\n');
}
