/* Safe Markdown for answers: builds DOM nodes with textContent only, never HTML.
 * Supports paragraphs, headings, lists, quotes, fenced code, GFM tables, links
 * (http, https, mailto), emphasis, inline code and regulAI masking markers.
 * render(root, source, {streaming}) reuses unchanged block nodes, so a growing
 * answer only rebuilds its last block; while streaming, open markers are closed. */
(() => {
  'use strict';
  const MARKER = /\[\[REGULAI_(PERSON|LOCATION|ORGANIZATION|EMAIL|PHONE|ID|ACCOUNT|CARD|SECRET)\]\]/;
  const MARKERS = new RegExp(MARKER.source, 'g');
  const MARKER_LABEL = {PERSON: 'nombre', LOCATION: 'ubicación', ORGANIZATION: 'organización', EMAIL: 'correo',
    PHONE: 'teléfono', ID: 'documento', ACCOUNT: 'cuenta', CARD: 'tarjeta', SECRET: 'secreto'};
  const SAFE_URL = /^(?:https?:\/\/|mailto:)[^\s<>"']+$/i;
  const FENCE = /^ {0,3}(`{3,}|~{3,})\s*([\w#+.-]*)\s*$/;
  const HEADING = /^ {0,3}(#{1,6})\s+(.*?)\s*#*\s*$/;
  const RULE = /^ {0,3}([-*_])(?:\s*\1){2,}\s*$/;
  const ITEM = /^( *)([-*+]|\d{1,9}[.)])\s+(.*)$/;
  const TABLE_DIVIDER = /^\s*\|?\s*:?-{2,}:?\s*(?:\|\s*:?-{2,}:?\s*)*\|?\s*$/;
  const QUOTE = /^ {0,3}> ?(.*)$/;

  function el(tag, className, text) {
    const node = document.createElement(tag);
    if (className) node.className = className;
    if (text != null) node.textContent = text;
    return node;
  }

  /* ---------------------------------------------------------- blocks */
  function blocks(source) {
    const lines = String(source || '').replace(/\r\n?/g, '\n').split('\n');
    const out = [];
    let i = 0;
    const isTableStart = index => index + 1 < lines.length && lines[index].includes('|') && TABLE_DIVIDER.test(lines[index + 1]);
    while (i < lines.length) {
      const line = lines[i];
      if (!line.trim()) { i++; continue; }
      const fence = line.match(FENCE);
      if (fence) {
        const start = i++;
        const body = [];
        while (i < lines.length && !(lines[i].trim().startsWith(fence[1][0].repeat(fence[1].length)) && !lines[i].trim().slice(fence[1].length).trim())) body.push(lines[i++]);
        const closed = i < lines.length;
        if (closed) i++;
        out.push({type: 'code', lang: fence[2], text: body.join('\n'), closed, raw: lines.slice(start, i).join('\n')});
        continue;
      }
      const heading = line.match(HEADING);
      if (heading) { out.push({type: 'heading', level: heading[1].length, text: heading[2], raw: line}); i++; continue; }
      if (RULE.test(line)) { out.push({type: 'rule', raw: line}); i++; continue; }
      if (isTableStart(i)) {
        const start = i;
        const rows = [line, lines[i + 1]];
        i += 2;
        while (i < lines.length && lines[i].includes('|') && lines[i].trim()) rows.push(lines[i++]);
        out.push({type: 'table', rows, raw: rows.join('\n'), start});
        continue;
      }
      if (QUOTE.test(line)) {
        const start = i;
        const body = [];
        while (i < lines.length && QUOTE.test(lines[i])) body.push(lines[i++].match(QUOTE)[1]);
        out.push({type: 'quote', text: body.join('\n'), raw: lines.slice(start, i).join('\n')});
        continue;
      }
      if (ITEM.test(line)) {
        const start = i;
        const items = [];
        while (i < lines.length) {
          const current = lines[i];
          const item = current.match(ITEM);
          if (item) { items.push({indent: item[1].length, ordered: /\d/.test(item[2]), marker: item[2], lines: [item[3]]}); i++; continue; }
          if (!current.trim()) {
            const next = lines[i + 1];
            if (next !== undefined && (ITEM.test(next) || /^ {2,}\S/.test(next))) { i++; continue; }
            break;
          }
          if (/^ {2,}\S/.test(current) || (!FENCE.test(current) && !HEADING.test(current) && !QUOTE.test(current) && !isTableStart(i))) {
            items[items.length - 1].lines.push(current.trim()); i++; continue;
          }
          break;
        }
        out.push({type: 'list', items, raw: lines.slice(start, i).join('\n')});
        continue;
      }
      const start = i;
      const body = [];
      while (i < lines.length && lines[i].trim() && !FENCE.test(lines[i]) && !HEADING.test(lines[i]) && !RULE.test(lines[i])
             && !QUOTE.test(lines[i]) && !(body.length && ITEM.test(lines[i])) && !isTableStart(i)) body.push(lines[i++]);
      out.push({type: 'paragraph', text: body.join('\n'), raw: lines.slice(start, i).join('\n')});
    }
    return out;
  }

  /* ---------------------------------------------------------- inline */
  function closeOpenMarkers(text) {
    // Streaming only: show **bold** or `code` as it grows instead of raw markers.
    let result = text;
    const ticks = (result.match(/`/g) || []).length;
    if (ticks % 2) result += '`';
    for (const marker of ['**', '~~']) {
      const count = result.split(marker).length - 1;
      if (count % 2) result += marker;
    }
    return result.replace(/\[([^\]]*)\]\([^)]*$/, '$1').replace(/\[([^\]]*)$/, '$1');
  }

  const LINKS = new Set(['link', 'autolink', 'url']);
  const INLINE = [
    ['code', /`([^`]+)`/],
    ['marker', MARKER],
    // URLs may hold balanced parentheses (Wikipedia titles): one level is kept.
    ['link', /\[([^\]]+)\]\(\s*((?:[^()\s]|\([^()\s]*\))+)(?:\s+"[^"]*")?\s*\)/],
    ['autolink', /<((?:https?:\/\/|mailto:)[^\s>]+)>/i],
    ['url', /\bhttps?:\/\/(?:[^\s<>()"']|\([^\s<>()"']*\))*(?:[^\s<>()"'.,;:!?]|\([^\s<>()"']*\))/i],
    ['strong', /\*\*([^*]+(?:\*(?!\*)[^*]*)*)\*\*|__([^_]+)__/],
    ['strike', /~~([^~]+)~~/],
    ['em', /(?<![*\w])\*([^*\s][^*]*?)\*(?!\*)|(?<![_\w])_([^_\s][^_]*?)_(?![_\w])/],
    ['cite', /\[(\d{1,2})\](?!\()/],
    ['break', / {2,}\n|\\\n/],
  ];
  const IN_LINK = INLINE.filter(([kind]) => !LINKS.has(kind));

  function inline(parent, text, links = true) {
    // A link's label is never searched for links again (no nested anchors).
    let rest = text;
    const patterns = links ? INLINE : IN_LINK;
    while (rest) {
      let best = null;
      for (const [kind, pattern] of patterns) {
        const match = pattern.exec(rest);
        if (match && (!best || match.index < best.match.index)) best = {kind, match};
      }
      if (!best) { parent.appendChild(document.createTextNode(rest)); break; }
      const {kind, match} = best;
      if (match.index) parent.appendChild(document.createTextNode(rest.slice(0, match.index)));
      if (kind === 'code') parent.appendChild(el('code', null, match[1]));
      else if (kind === 'marker') {
        const chip = el('span', 'rg-redacted', MARKER_LABEL[match[1]] + ' protegido');
        chip.title = 'Dato enmascarado antes de salir de la organización';
        parent.appendChild(chip);
      } else if (kind === 'link' || kind === 'autolink' || kind === 'url') {
        const url = kind === 'link' ? match[2] : (kind === 'autolink' ? match[1] : match[0]);
        const label = kind === 'link' ? match[1] : url;
        if (SAFE_URL.test(url)) {
          const link = el('a');
          link.href = url; link.target = '_blank'; link.rel = 'noopener noreferrer nofollow';
          inline(link, label, false);
          parent.appendChild(link);
        } else parent.appendChild(document.createTextNode(label));
      } else if (kind === 'strong') inline(parent.appendChild(el('strong')), match[1] || match[2], links);
      else if (kind === 'strike') inline(parent.appendChild(el('del')), match[1], links);
      else if (kind === 'em') inline(parent.appendChild(el('em')), match[1] || match[2], links);
      else if (kind === 'cite') {
        const cite = el('sup', 'rg-cite', match[1]);
        cite.dataset.cite = match[1];
        parent.appendChild(cite);
      } else if (kind === 'break') parent.appendChild(el('br'));
      rest = rest.slice(match.index + match[0].length);
    }
    return parent;
  }

  function cells(row) {
    let value = row.trim();
    if (value.startsWith('|')) value = value.slice(1);
    if (value.endsWith('|') && !value.endsWith('\\|')) value = value.slice(0, -1);
    return value.split(/(?<!\\)\|/).map(cell => cell.trim().replace(/\\\|/g, '|'));
  }

  function listNode(items, start, indent) {
    const ordered = items[start].ordered;
    const list = el(ordered ? 'ol' : 'ul');
    if (ordered) {
      const first = parseInt(items[start].marker, 10);
      if (first > 1) list.setAttribute('start', String(first));
    }
    let index = start;
    while (index < items.length && items[index].indent >= indent) {
      const item = items[index];
      if (item.indent > indent) { index++; continue; }
      const li = el('li');
      const task = item.lines[0].match(/^\[([ xX])\]\s+(.*)$/);
      if (task) {
        const box = el('span', 'rg-task' + (task[1].trim() ? ' is-done' : ''), task[1].trim() ? '✓' : '');
        box.setAttribute('aria-label', task[1].trim() ? 'Hecho' : 'Pendiente');
        li.appendChild(box);
        inline(li, [task[2], ...item.lines.slice(1)].join('\n'));
      } else inline(li, item.lines.join('\n'));
      index++;
      if (index < items.length && items[index].indent > indent) {
        const nested = listNode(items, index, items[index].indent);
        li.appendChild(nested.node);
        index = nested.next;
      }
      list.appendChild(li);
    }
    return {node: list, next: index};
  }

  function blockNode(block, streaming) {
    switch (block.type) {
      case 'heading': return inline(el('h' + Math.min(6, block.level + 1)), block.text);
      case 'rule': return el('hr');
      case 'quote': {
        const quote = el('blockquote');
        render(quote, block.text, {streaming});
        return quote;
      }
      case 'code': {
        const figure = el('figure', 'rg-code');
        const bar = el('figcaption', 'rg-code-bar');
        bar.appendChild(el('span', 'rg-code-lang', block.lang || 'texto'));
        const copy = el('button', 'rg-code-copy', 'Copiar');
        copy.type = 'button';
        copy.setAttribute('aria-label', 'Copiar código');
        copy.dataset.copy = block.text;
        bar.appendChild(copy);
        figure.appendChild(bar);
        const pre = el('pre');
        const code = el('code', null, block.text);
        if (block.lang) code.dataset.lang = block.lang;
        pre.appendChild(code);
        figure.appendChild(pre);
        if (!block.closed && streaming) figure.classList.add('is-open');
        return figure;
      }
      case 'table': {
        const wrap = el('div', 'rg-table');
        wrap.tabIndex = 0;
        wrap.setAttribute('role', 'region');
        wrap.setAttribute('aria-label', 'Tabla');
        const table = el('table');
        const aligns = cells(block.rows[1]).map(cell => cell.startsWith(':') && cell.endsWith(':') ? 'center' : cell.endsWith(':') ? 'right' : '');
        const head = table.appendChild(el('thead')).appendChild(el('tr'));
        cells(block.rows[0]).forEach((cell, index) => {
          const th = inline(el('th'), cell);
          th.setAttribute('scope', 'col');
          if (aligns[index]) th.style.textAlign = aligns[index];
          head.appendChild(th);
        });
        const body = table.appendChild(el('tbody'));
        block.rows.slice(2).forEach(row => {
          const tr = body.appendChild(el('tr'));
          cells(row).forEach((cell, index) => {
            const td = inline(el('td'), cell);
            if (aligns[index]) td.style.textAlign = aligns[index];
            tr.appendChild(td);
          });
        });
        wrap.appendChild(table);
        return wrap;
      }
      case 'list': return listNode(block.items, 0, block.items[0].indent).node;
      default: return inline(el('p'), streaming ? closeOpenMarkers(block.text) : block.text);
    }
  }

  function render(root, source, {streaming = false, animate = false} = {}) {
    const next = blocks(source);
    const tail = next[next.length - 1];
    const openTail = streaming && Boolean(tail) && !(tail.type === 'code' && tail.closed)
      && !(tail.type === 'paragraph' && /\n[ \t]*\n[ \t\n]*$/.test(String(source || '')));
    if (openTail && next.length) {
      const last = next[next.length - 1];
      if (last.type === 'paragraph') {
        // A trailing "| a | b |" line may become a table header: wait for its divider.
        const lines = last.text.split('\n');
        if (/^\s*\|/.test(lines[lines.length - 1])) lines.pop();
        if (lines.length) last.text = closeOpenMarkers(lines.join('\n'));
        else next.pop();
      } else if (last.type === 'list') {
        const item = last.items[last.items.length - 1];
        item.lines = closeOpenMarkers(item.lines.join('\n')).split('\n');
      } else if (last.type === 'heading') last.text = closeOpenMarkers(last.text);
    }
    const previous = root._rgBlocks || [];
    const kept = [];
    let index = 0;
    for (; index < next.length; index++) {
      const old = previous[index];
      const isLast = index === next.length - 1;
      if (old && old.raw === next[index].raw && old.type === next[index].type && !(openTail && isLast) && !old.streaming) {
        kept.push(old);
        continue;
      }
      break;
    }
    for (let stale = index; stale < previous.length; stale++) previous[stale].node.remove();
    for (; index < next.length; index++) {
      const node = blockNode(next[index], openTail && index === next.length - 1);
      const isNew = index >= previous.length;
      if (animate && isNew) node.classList.add('rg-enter');
      root.appendChild(node);
      kept.push({...next[index], node, streaming: openTail && index === next.length - 1});
    }
    root._rgBlocks = kept;
    return root;
  }

  function plain(source) {
    return String(source || '').replace(MARKERS, (_, kind) => '[' + MARKER_LABEL[kind] + ' protegido]');
  }

  window.RegulayMarkdown = {render, blocks, plain};
})();
