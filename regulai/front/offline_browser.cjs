'use strict';
/* Offline browser for the chat page: a small DOM, fake timers and a scripted network.
 *
 * Enough DOM for chat-markdown.js, chat.js and agent-chat.js. Pages come from
 * Django's test client, parsed by Python's html.parser into [tag, attributes,
 * children] trees (see offline_browser.py). The scripts run in this realm with
 * browser globals installed; innerHTML, outerHTML and insertAdjacentHTML throw,
 * so any attempt to insert markup fails the test.
 *
 * stdin (JSON): {tree, scripts: [{name, source}], checks, options}
 * Exit code 0 when the checks pass; otherwise the error is written to stderr.
 */
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');

const realSetImmediate = setImmediate;
const HTML = 'http://www.w3.org/1999/xhtml';
const SVG = 'http://www.w3.org/2000/svg';
const SVG_TAGS = new Set(['svg', 'use', 'path', 'symbol', 'g', 'circle', 'rect', 'line', 'polyline', 'polygon', 'defs']);
const INLINE = new Set(['a', 'abbr', 'b', 'code', 'del', 'em', 'i', 'kbd', 'mark', 'q', 's', 'strong', 'sub', 'sup', 'u']);
const NO_TEXT = new Set(['script', 'style', 'template', 'svg', 'head', 'title']);

/* ------------------------------------------------------------------ events */
class Event {
  constructor(type, init = {}) {
    this.type = String(type);
    this.bubbles = Boolean(init.bubbles);
    this.cancelable = Boolean(init.cancelable);
    this.defaultPrevented = false;
    this.target = null;
    this.currentTarget = null;
    this.isTrusted = false;
    this.timeStamp = 0;
    this._stop = false;
    this._stopNow = false;
  }
  preventDefault() { if (this.cancelable) this.defaultPrevented = true; }
  stopPropagation() { this._stop = true; }
  stopImmediatePropagation() { this._stop = true; this._stopNow = true; }
}
class CustomEvent extends Event {
  constructor(type, init = {}) { super(type, init); this.detail = init.detail ?? null; }
}
class MouseEvent extends Event {
  constructor(type, init = {}) {
    super(type, init);
    for (const key of ['button', 'clientX', 'clientY']) this[key] = init[key] || 0;
    for (const key of ['shiftKey', 'ctrlKey', 'altKey', 'metaKey']) this[key] = Boolean(init[key]);
  }
}
class KeyboardEvent extends Event {
  constructor(type, init = {}) {
    super(type, init);
    this.key = init.key || '';
    this.code = init.code || '';
    this.keyCode = init.keyCode || 0;
    this.isComposing = Boolean(init.isComposing);
    for (const key of ['shiftKey', 'ctrlKey', 'altKey', 'metaKey']) this[key] = Boolean(init[key]);
  }
}
class FocusEvent extends Event {}
class DragEvent extends MouseEvent {
  constructor(type, init = {}) { super(type, init); this.dataTransfer = init.dataTransfer || null; }
}

class Target {
  constructor() { this._listeners = new Map(); }
  addEventListener(type, callback, options) {
    if (!callback) return;
    const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
    const items = this._listeners.get(type) || [];
    if (items.some(item => item.callback === callback && item.capture === capture)) return;
    items.push({callback, capture, once: Boolean(typeof options === 'object' && options?.once)});
    this._listeners.set(type, items);
  }
  removeEventListener(type, callback, options) {
    const capture = typeof options === 'boolean' ? options : Boolean(options?.capture);
    this._listeners.set(type, (this._listeners.get(type) || []).filter(item => !(item.callback === callback && item.capture === capture)));
  }
  _invoke(event) {
    for (const item of [...(this._listeners.get(event.type) || [])]) {
      if (item.once) this.removeEventListener(event.type, item.callback, item.capture);
      event.currentTarget = this;
      if (typeof item.callback === 'function') item.callback.call(this, event);
      else item.callback.handleEvent(event);
      if (event._stopNow) return;
    }
    const handler = this['on' + event.type];
    if (typeof handler === 'function') handler.call(this, event);
  }
  dispatchEvent(event) {
    event.target = this;
    const path = [];
    for (let node = this; node; node = node._eventParent()) path.push(node);
    for (const node of event.bubbles ? path : [this]) {
      node._invoke(event);
      if (event._stop) break;
    }
    event.currentTarget = null;
    return !event.defaultPrevented;
  }
  _eventParent() { return null; }
}

/* ------------------------------------------------------------------ selectors */
const selectorCache = new Map();
function split(text, separator) {
  const parts = [];
  let depth = 0, quote = null, start = 0;
  for (let index = 0; index < text.length; index++) {
    const char = text[index];
    if (quote) { if (char === quote) quote = null; continue; }
    if (char === '"' || char === "'") quote = char;
    else if (char === '(' || char === '[') depth++;
    else if (char === ')' || char === ']') depth--;
    else if (char === separator && !depth) { parts.push(text.slice(start, index)); start = index + 1; }
  }
  parts.push(text.slice(start));
  return parts;
}
function closing(text, index, open, close) {
  let depth = 0, quote = null;
  for (let at = index; at < text.length; at++) {
    const char = text[at];
    if (quote) { if (char === quote) quote = null; continue; }
    if (char === '"' || char === "'") quote = char;
    else if (char === open) depth++;
    else if (char === close && !--depth) return at;
  }
  throw new Error('Unbalanced selector: ' + text);
}
function parseCompound(text, index) {
  const compound = {tag: null, id: null, classes: [], attributes: [], pseudos: []};
  while (index < text.length && !/[\s>+~]/.test(text[index])) {
    const rest = text.slice(index), char = text[index];
    let match;
    if (char === '*') { index++; continue; }
    if (char === '#' && (match = /^#([\w-]+)/.exec(rest))) { compound.id = match[1]; index += match[0].length; continue; }
    if (char === '.' && (match = /^\.([\w-]+)/.exec(rest))) { compound.classes.push(match[1]); index += match[0].length; continue; }
    if (char === '[') {
      const end = closing(text, index, '[', ']');
      match = /^\s*([\w:-]+)\s*(?:([~|^$*]?=)\s*(?:"([^"]*)"|'([^']*)'|([^\s\]]+)))?\s*$/.exec(text.slice(index + 1, end));
      if (!match) throw new Error('Unsupported attribute selector: ' + text);
      compound.attributes.push({name: match[1].toLowerCase(), operator: match[2] || null, value: match[3] ?? match[4] ?? match[5] ?? null});
      index = end + 1;
      continue;
    }
    if (char === ':' && (match = /^:([\w-]+)/.exec(rest))) {
      index += match[0].length;
      let argument = null;
      if (text[index] === '(') {
        const end = closing(text, index, '(', ')');
        argument = text.slice(index + 1, end);
        index = end + 1;
      }
      compound.pseudos.push({name: match[1], argument: ['not', 'is', 'where'].includes(match[1]) ? parseSelector(argument) : argument});
      continue;
    }
    if ((match = /^[\w-]+/.exec(rest))) { compound.tag = match[0].toLowerCase(); index += match[0].length; continue; }
    throw new Error('Unsupported selector: ' + text);
  }
  return [compound, index];
}
function parseComplex(text) {
  const steps = [];
  let index = 0, combinator = null;
  while (index < text.length) {
    let space = false;
    while (index < text.length && /\s/.test(text[index])) { index++; space = true; }
    if (index >= text.length) break;
    if ('>+~'.includes(text[index])) { combinator = text[index++]; continue; }
    if (space && steps.length && !combinator) combinator = ' ';
    const [compound, next] = parseCompound(text, index);
    steps.push({compound, combinator: steps.length ? combinator || ' ' : null});
    combinator = null;
    index = next;
  }
  if (!steps.length) throw new Error('Empty selector');
  return steps;
}
function parseSelector(source) {
  if (!selectorCache.has(source)) selectorCache.set(source, split(String(source), ',').map(part => parseComplex(part.trim())));
  return selectorCache.get(source);
}
function matchesCompound(element, compound, scope) {
  if (compound.tag && element.localName !== compound.tag) return false;
  if (compound.id && element.getAttribute('id') !== compound.id) return false;
  if (compound.classes.length) {
    const classes = (element.getAttribute('class') || '').split(/\s+/);
    if (!compound.classes.every(name => classes.includes(name))) return false;
  }
  for (const {name, operator, value} of compound.attributes) {
    const actual = element.getAttribute(name);
    if (actual === null) return false;
    if (operator === '=' && actual !== value) return false;
    if (operator === '~=' && !actual.split(/\s+/).includes(value)) return false;
    if (operator === '^=' && !actual.startsWith(value)) return false;
    if (operator === '$=' && !actual.endsWith(value)) return false;
    if (operator === '*=' && !actual.includes(value)) return false;
    if (operator === '|=' && actual !== value && !actual.startsWith(value + '-')) return false;
  }
  for (const {name, argument} of compound.pseudos) {
    if (name === 'not') { if (argument.some(steps => matchesComplex(element, steps, scope))) return false; }
    else if (name === 'is' || name === 'where') { if (!argument.some(steps => matchesComplex(element, steps, scope))) return false; }
    else if (name === 'checked') { if (!element.checked) return false; }
    else if (name === 'disabled') { if (!element.hasAttribute('disabled')) return false; }
    else if (name === 'enabled') { if (element.hasAttribute('disabled')) return false; }
    else if (name === 'scope') { if (element !== scope) return false; }
    else if (name === 'first-child') { if (element.parentNode?.children[0] !== element) return false; }
    else if (name === 'last-child') { if (element.parentNode?.children.at(-1) !== element) return false; }
    else throw new Error('Unsupported pseudo-class :' + name);
  }
  return true;
}
function matchesComplex(element, steps, scope) {
  const test = (node, index) => {
    if (!matchesCompound(node, steps[index].compound, scope)) return false;
    if (index === 0) return true;
    const combinator = steps[index].combinator;
    if (combinator === '>') return Boolean(node.parentElement) && test(node.parentElement, index - 1);
    if (combinator === '+') return Boolean(node.previousElementSibling) && test(node.previousElementSibling, index - 1);
    if (combinator === '~') {
      for (let sibling = node.previousElementSibling; sibling; sibling = sibling.previousElementSibling) if (test(sibling, index - 1)) return true;
      return false;
    }
    for (let parent = node.parentElement; parent; parent = parent.parentElement) if (test(parent, index - 1)) return true;
    return false;
  };
  return test(element, steps.length - 1);
}
function descendants(root) {
  const out = [];
  const visit = node => {
    for (const child of node.childNodes) {
      if (child.nodeType === 1) { out.push(child); visit(child); }
      else if (child.nodeType === 11) visit(child);
    }
  };
  visit(root);
  return out;
}
function query(root, selector, first) {
  const parsed = parseSelector(selector), found = [];
  for (const element of descendants(root)) {
    if (parsed.some(steps => matchesComplex(element, steps, root))) {
      found.push(element);
      if (first) break;
    }
  }
  return found;
}

/* ------------------------------------------------------------------ nodes */
class Node extends Target {
  constructor(document, nodeType) {
    super();
    this.ownerDocument = document;
    this.nodeType = nodeType;
    this.parentNode = null;
    this.childNodes = [];
  }
  get parentElement() { return this.parentNode?.nodeType === 1 ? this.parentNode : null; }
  get children() { return this.childNodes.filter(node => node.nodeType === 1); }
  get childElementCount() { return this.children.length; }
  get firstChild() { return this.childNodes[0] || null; }
  get lastChild() { return this.childNodes.at(-1) || null; }
  get firstElementChild() { return this.children[0] || null; }
  get lastElementChild() { return this.children.at(-1) || null; }
  _sibling(step, elements) {
    if (!this.parentNode) return null;
    const siblings = this.parentNode.childNodes;
    for (let index = siblings.indexOf(this) + step; index >= 0 && index < siblings.length; index += step) {
      if (!elements || siblings[index].nodeType === 1) return siblings[index];
    }
    return null;
  }
  get nextSibling() { return this._sibling(1, false); }
  get previousSibling() { return this._sibling(-1, false); }
  get nextElementSibling() { return this._sibling(1, true); }
  get previousElementSibling() { return this._sibling(-1, true); }
  get isConnected() {
    let node = this;
    while (node.parentNode) node = node.parentNode;
    return node.nodeType === 9;
  }
  _eventParent() { return this.parentNode; }
  contains(other) {
    for (let node = other; node; node = node.parentNode) if (node === this) return true;
    return false;
  }
  hasChildNodes() { return this.childNodes.length > 0; }
  insertBefore(child, reference) {
    if (child.nodeType === 11) {
      for (const node of [...child.childNodes]) this.insertBefore(node, reference);
      return child;
    }
    if (child.contains(this)) throw new Error('HierarchyRequestError');
    child.remove();
    const index = reference ? this.childNodes.indexOf(reference) : -1;
    if (index < 0) this.childNodes.push(child);
    else this.childNodes.splice(index, 0, child);
    child.parentNode = this;
    return child;
  }
  appendChild(child) { return this.insertBefore(child, null); }
  removeChild(child) {
    const index = this.childNodes.indexOf(child);
    if (index < 0) throw new Error('NotFoundError');
    this.childNodes.splice(index, 1);
    child.parentNode = null;
    return child;
  }
  replaceChild(next, previous) { this.insertBefore(next, previous); return this.removeChild(previous); }
  remove() { this.parentNode?.removeChild(this); }
  _nodes(items) { return items.map(item => typeof item === 'object' && item ? item : this._document().createTextNode(String(item))); }
  _document() { return this.nodeType === 9 ? this : this.ownerDocument; }
  append(...items) { for (const node of this._nodes(items)) this.appendChild(node); }
  prepend(...items) {
    const first = this.firstChild;
    for (const node of this._nodes(items)) this.insertBefore(node, first);
  }
  replaceChildren(...items) {
    for (const node of [...this.childNodes]) this.removeChild(node);
    this.append(...items);
  }
  after(...items) {
    const parent = this.parentNode, next = this.nextSibling;
    if (parent) for (const node of this._nodes(items)) parent.insertBefore(node, next);
  }
  before(...items) {
    const parent = this.parentNode;
    if (parent) for (const node of this._nodes(items)) parent.insertBefore(node, this);
  }
  replaceWith(...items) {
    const parent = this.parentNode, next = this.nextSibling;
    if (!parent) return;
    this.remove();
    for (const node of this._nodes(items)) parent.insertBefore(node, next);
  }
  get textContent() { return this.childNodes.map(node => node.nodeType === 8 ? '' : node.textContent).join(''); }
  set textContent(value) {
    for (const node of [...this.childNodes]) this.removeChild(node);
    const text = value == null ? '' : String(value);
    if (text) this.appendChild(this._document().createTextNode(text));
  }
  querySelector(selector) { return query(this, selector, true)[0] || null; }
  querySelectorAll(selector) { return query(this, selector, false); }
}

class Text extends Node {
  constructor(document, data) { super(document, 3); this.data = String(data); }
  get nodeName() { return '#text'; }
  get nodeValue() { return this.data; }
  get textContent() { return this.data; }
  set textContent(value) { this.data = value == null ? '' : String(value); }
}
class Comment extends Node {
  constructor(document, data) { super(document, 8); this.data = String(data); }
  get textContent() { return this.data; }
}
class Fragment extends Node {
  constructor(document) { super(document, 11); }
}

function datasetOf(element) {
  const attribute = key => 'data-' + String(key).replace(/[A-Z]/g, char => '-' + char.toLowerCase());
  const key = name => name.slice(5).replace(/-([a-z])/g, (_, char) => char.toUpperCase());
  return new Proxy({}, {
    get: (_, name) => typeof name === 'string' && element.hasAttribute(attribute(name)) ? element.getAttribute(attribute(name)) : undefined,
    set: (_, name, value) => { element.setAttribute(attribute(name), String(value)); return true; },
    has: (_, name) => typeof name === 'string' && element.hasAttribute(attribute(name)),
    deleteProperty: (_, name) => { element.removeAttribute(attribute(name)); return true; },
    ownKeys: () => element.getAttributeNames().filter(name => name.startsWith('data-')).map(key),
    getOwnPropertyDescriptor: (_, name) => typeof name === 'string' && element.hasAttribute(attribute(name)) ?
      {enumerable: true, configurable: true, writable: true, value: element.getAttribute(attribute(name))} : undefined,
  });
}
function classListOf(element) {
  const read = () => (element.getAttribute('class') || '').split(/\s+/).filter(Boolean);
  const write = names => element.setAttribute('class', [...new Set(names)].join(' '));
  return {
    add: (...names) => write([...read(), ...names]),
    remove: (...names) => write(read().filter(name => !names.includes(name))),
    contains: name => read().includes(name),
    toggle(name, force) {
      const on = force === undefined ? !read().includes(name) : Boolean(force);
      if (on) this.add(name); else this.remove(name);
      return on;
    },
    replace(before, after) { if (!read().includes(before)) return false; write(read().map(name => name === before ? after : name)); return true; },
    get length() { return read().length; },
    get value() { return read().join(' '); },
    [Symbol.iterator]: () => read()[Symbol.iterator](),
  };
}
function styleOf() {
  const style = {};
  Object.defineProperties(style, {
    setProperty: {value: (name, value) => { style[name] = String(value); }},
    getPropertyValue: {value: name => style[name] ?? ''},
    removeProperty: {value: name => { delete style[name]; }},
  });
  return style;
}
function fileList(files) {
  const items = [...files];
  items.item = index => items[index] || null;
  return items;
}

class Element extends Node {
  constructor(document, name, namespace) {
    super(document, 1);
    this.namespaceURI = namespace || (SVG_TAGS.has(String(name).toLowerCase()) ? SVG : HTML);
    this.localName = String(name).toLowerCase();
    this._attributes = new Map();
    this.style = styleOf();
    this.dataset = datasetOf(this);
    this.classList = classListOf(this);
    this.scrollTop = 0;
    this.scrollHeight = 0;
    this.clientHeight = 0;
    this.offsetHeight = 0;
  }
  get tagName() { return this.localName.toUpperCase(); }
  get nodeName() { return this.tagName; }
  getAttribute(name) { name = String(name).toLowerCase(); return this._attributes.has(name) ? this._attributes.get(name) : null; }
  setAttribute(name, value) { this._attributes.set(String(name).toLowerCase(), String(value)); }
  removeAttribute(name) { this._attributes.delete(String(name).toLowerCase()); }
  hasAttribute(name) { return this._attributes.has(String(name).toLowerCase()); }
  toggleAttribute(name, force) {
    const on = force === undefined ? !this.hasAttribute(name) : Boolean(force);
    if (on) this.setAttribute(name, ''); else this.removeAttribute(name);
    return on;
  }
  getAttributeNames() { return [...this._attributes.keys()]; }
  get attributes() { return [...this._attributes].map(([name, value]) => ({name, value})); }
  matches(selector) { return parseSelector(selector).some(steps => matchesComplex(this, steps, this)); }
  closest(selector) {
    const parsed = parseSelector(selector);
    for (let node = this; node?.nodeType === 1; node = node.parentNode) if (parsed.some(steps => matchesComplex(node, steps, node))) return node;
    return null;
  }
  get innerHTML() { throw new Error('innerHTML is not allowed: build nodes and insert text'); }
  set innerHTML(_) { throw new Error('innerHTML is not allowed: build nodes and insert text'); }
  get outerHTML() { throw new Error('outerHTML is not allowed'); }
  set outerHTML(_) { throw new Error('outerHTML is not allowed'); }
  insertAdjacentHTML() { throw new Error('insertAdjacentHTML is not allowed'); }
  get checked() { return this._checked ?? this.hasAttribute('checked'); }
  set checked(value) { this._checked = Boolean(value); }
  get value() {
    if (this._value !== undefined) return this._value;
    if (this.localName === 'textarea') return this.textContent;
    if (this.localName === 'input' && this.type === 'file') return this.files.length ? 'C:\\fakepath\\' + this.files[0].name : '';
    return this.getAttribute('value') ?? (['checkbox', 'radio'].includes(this.type) ? 'on' : '');
  }
  set value(value) {
    if (this.localName === 'input' && this.type === 'file') {
      if (value === '' || value == null) this._files = fileList([]);
      return;
    }
    this._value = value == null ? '' : String(value);
  }
  get files() { return this.localName === 'input' && this.type === 'file' ? (this._files ||= fileList([])) : undefined; }
  set files(value) { this._files = fileList(Array.from(value || [])); }
  get tabIndex() {
    const value = parseInt(this.getAttribute('tabindex'), 10);
    if (Number.isFinite(value)) return value;
    return ['a', 'button', 'input', 'select', 'textarea', 'summary'].includes(this.localName) ? 0 : -1;
  }
  set tabIndex(value) { this.setAttribute('tabindex', String(value)); }
  get maxLength() { const value = parseInt(this.getAttribute('maxlength'), 10); return Number.isFinite(value) ? value : -1; }
  set maxLength(value) { this.setAttribute('maxlength', String(value)); }
  focus() { this.ownerDocument._focus(this); }
  blur() { if (this.ownerDocument._active === this) this.ownerDocument._focus(null); }
  select() {}
  setSelectionRange() {}
  scrollTo(options) {
    if (options && typeof options === 'object' && 'top' in options) this.scrollTop = options.top;
  }
  scrollIntoView() { this.ownerDocument.defaultView.scrolledIntoView.push(this); }
  getBoundingClientRect() { return {top: 0, left: 0, right: 0, bottom: 0, width: 0, height: 0, x: 0, y: 0}; }
  showModal() { this.setAttribute('open', ''); this.modal = true; }
  show() { this.setAttribute('open', ''); }
  close(returnValue) {
    if (!this.hasAttribute('open')) return;
    this.removeAttribute('open');
    this.modal = false;
    this.returnValue = returnValue ?? '';
    this.dispatchEvent(new Event('close'));
  }
  requestSubmit(submitter = null) {
    const event = new Event('submit', {bubbles: true, cancelable: true});
    event.submitter = submitter;
    if (this.dispatchEvent(event)) this.ownerDocument.defaultView.navigations.push({form: this});
  }
  click() {
    if (this.hasAttribute('disabled') && ['button', 'input', 'select', 'textarea'].includes(this.localName)) return;
    const toggles = this.localName === 'input' && ['checkbox', 'radio'].includes(this.type);
    const before = this.checked;
    if (toggles) {
      if (this.type === 'radio') {
        for (const other of this.ownerDocument.querySelectorAll(`input[type=radio][name="${this.name}"]`)) other.checked = false;
        this.checked = true;
      } else this.checked = !before;
    }
    const proceed = this.dispatchEvent(new MouseEvent('click', {bubbles: true, cancelable: true}));
    if (toggles) {
      if (!proceed) this.checked = before;
      else if (this.checked !== before) {
        this.dispatchEvent(new Event('input', {bubbles: true}));
        this.dispatchEvent(new Event('change', {bubbles: true}));
      }
      return;
    }
    if (!proceed) return;
    if (this.localName === 'label') {
      const control = this.htmlFor ? this.ownerDocument.getElementById(this.htmlFor) : this.querySelector('input, textarea, select, button');
      control?.click();
      return;
    }
    if (this.localName === 'summary' && this.parentNode?.localName === 'details') {
      this.parentNode.open = !this.parentNode.open;
      this.parentNode.dispatchEvent(new Event('toggle'));
      return;
    }
    const form = this.closest('form');
    if (form && ['button', 'input'].includes(this.localName) && this.type === 'submit') form.requestSubmit(this);
  }
}
const REFLECTED = {id: 'id', className: 'class', title: 'title', href: 'href', src: 'src', alt: 'alt', rel: 'rel',
  target: 'target', name: 'name', placeholder: 'placeholder', accept: 'accept', htmlFor: 'for', loading: 'loading',
  lang: 'lang', autocomplete: 'autocomplete', download: 'download'};
for (const [property, attribute] of Object.entries(REFLECTED)) {
  Object.defineProperty(Element.prototype, property, {configurable: true,
    get() { return this.getAttribute(attribute) ?? ''; }, set(value) { this.setAttribute(attribute, value); }});
}
Object.defineProperty(Element.prototype, 'type', {configurable: true,
  get() {
    const value = this.getAttribute('type');
    if (value !== null) return value.toLowerCase();
    return this.localName === 'button' ? 'submit' : this.localName === 'input' ? 'text' : '';
  },
  set(value) { this.setAttribute('type', value); }});
for (const [property, attribute] of Object.entries({hidden: 'hidden', disabled: 'disabled', open: 'open', multiple: 'multiple',
  required: 'required', readOnly: 'readonly'})) {
  Object.defineProperty(Element.prototype, property, {configurable: true,
    get() { return this.hasAttribute(attribute); },
    set(value) { if (value) this.setAttribute(attribute, ''); else this.removeAttribute(attribute); }});
}

class Document extends Node {
  constructor(window) {
    super(null, 9);
    this.defaultView = window;
    this.readyState = 'loading';
    this._active = null;
  }
  get documentElement() { return this.children[0] || null; }
  get head() { return this.documentElement?.children.find(node => node.localName === 'head') || null; }
  get body() { return this.documentElement?.children.find(node => node.localName === 'body') || null; }
  get activeElement() { return this._active?.isConnected ? this._active : this.body; }
  get textContent() { return null; }
  _eventParent() { return this.defaultView.events; }
  createElement(name) { return new Element(this, name); }
  createElementNS(namespace, name) { return new Element(this, name, namespace); }
  createTextNode(text) { return new Text(this, text); }
  createComment(text) { return new Comment(this, text); }
  createDocumentFragment() { return new Fragment(this); }
  getElementById(id) { return descendants(this).find(node => node.getAttribute('id') === String(id)) || null; }
  execCommand() { return false; }
  _focus(element) {
    const previous = this._active;
    if (previous === element) return;
    this._active = element;
    if (previous) previous.dispatchEvent(new FocusEvent('focusout', {bubbles: true}));
    if (element) element.dispatchEvent(new FocusEvent('focusin', {bubbles: true}));
  }
}

/* ------------------------------------------------------------------ text */
function text(node, {hidden = true} = {}) {
  const out = [];
  const visit = current => {
    if (current.nodeType === 3) { out.push(current.data); return; }
    if (current.nodeType !== 1 && current.nodeType !== 9 && current.nodeType !== 11) return;
    if (current.nodeType === 1) {
      if (NO_TEXT.has(current.localName)) return;
      if (!hidden && (current.hasAttribute('hidden') || (current.localName === 'dialog' && !current.hasAttribute('open')))) return;
    }
    const block = current.nodeType === 1 && !INLINE.has(current.localName);
    if (block || current.localName === 'br') out.push('\n');
    const closed = !hidden && current.localName === 'details' && !current.hasAttribute('open');
    for (const child of current.childNodes) {
      if (closed && !(child.nodeType === 1 && child.localName === 'summary')) continue;
      visit(child);
    }
    if (block) out.push('\n');
  };
  visit(node);
  return out.join('').split('\n').map(line => line.replace(/[ \t\r\f]+/g, ' ').trim()).filter(Boolean).join('\n');
}

/* ------------------------------------------------------------------ browser */
function install(options) {
  const window = globalThis;
  const timers = new Map();
  let now = 0, nextTimer = 0;
  const setTimer = (callback, delay, args, interval) => {
    const id = ++nextTimer;
    timers.set(id, {at: now + Math.max(0, Number(delay) || 0), callback, args, interval});
    return id;
  };
  const flush = async (rounds = 12) => {
    for (let round = 0; round < rounds; round++) await new Promise(resolve => realSetImmediate(resolve));
  };
  const tick = async (milliseconds = 0) => {
    const end = now + milliseconds;
    await flush();
    for (;;) {
      const due = [...timers.entries()].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at || a[0] - b[0])[0];
      if (!due) break;
      const [id, timer] = due;
      now = timer.at;
      if (timer.interval != null) timer.at += Math.max(1, timer.interval);
      else timers.delete(id);
      timer.callback(...timer.args);
      await flush();
    }
    now = end;
    await flush();
  };

  const net = {
    requests: [],
    routes: [],
    on(pattern, handler, {once = false} = {}) { this.routes.push({pattern, handler, once}); return this; },
    json(body, {status = 200, headers = {}} = {}) { return respond(status, {'Content-Type': 'application/json', ...headers}, JSON.stringify(body)); },
    sse({status = 200} = {}) {
      let controller, open = true;
      const encoder = new TextEncoder();
      const body = new ReadableStream({start(value) { controller = value; }});
      return {
        response: respond(status, {'Content-Type': 'text/event-stream; charset=utf-8'}, null, body),
        send(...events) {
          for (const event of events) controller.enqueue(encoder.encode(`id: ${event.seq}\nevent: ${event.type}\ndata: ${JSON.stringify(event)}\n\n`));
        },
        raw(value) { controller.enqueue(encoder.encode(value)); },
        close() { if (open) { open = false; controller.close(); } },
        fail(message = 'network error') { if (open) { open = false; controller.error(new TypeError(message)); } },
      };
    },
    hold() {
      const held = {};
      held.promise = new Promise((resolve, reject) => { held.resolve = resolve; held.reject = reject; });
      return held;
    },
    find(method, url) {
      return this.requests.filter(request => request.method === method && (url instanceof RegExp ? url.test(request.url) : request.url === url));
    },
  };
  function respond(status, headers, body, stream = null) {
    const values = new Map(Object.entries(headers).map(([name, value]) => [name.toLowerCase(), String(value)]));
    return {ok: status >= 200 && status < 300, status,
      headers: {get: name => values.get(String(name).toLowerCase()) ?? null, has: name => values.has(String(name).toLowerCase())},
      body: stream || (body == null ? null : new ReadableStream({start(controller) { controller.enqueue(new TextEncoder().encode(body)); controller.close(); }})),
      json: async () => JSON.parse(body), text: async () => body ?? ''};
  }
  // Replies needed while the page loads (before the checks run): [{method, url, status, json}].
  for (const route of options.routes || []) {
    net.on((route.method ? route.method.toUpperCase() + ' ' : '') + route.url,
      () => respond(route.status || 200, {'Content-Type': 'application/json'}, JSON.stringify(route.json)));
  }
  const routeMatches = (pattern, request) => {
    if (typeof pattern === 'function') return pattern(request);
    if (pattern instanceof RegExp) return pattern.test(request.url);
    const [method, url] = pattern.includes(' ') ? pattern.split(' ') : [null, pattern];
    if (method && method !== request.method) return false;
    return url.endsWith('*') ? request.url.startsWith(url.slice(0, -1)) : request.url === url;
  };
  async function fetch(input, init = {}) {
    const headers = {};
    for (const [name, value] of Object.entries(init.headers || {})) headers[name.toLowerCase()] = String(value);
    const request = {url: String(input), method: String(init.method || 'GET').toUpperCase(), headers, body: init.body ?? null, init};
    net.requests.push(request);
    for (let index = net.routes.length - 1; index >= 0; index--) {
      const route = net.routes[index];
      if (!routeMatches(route.pattern, request)) continue;
      if (route.once) net.routes.splice(index, 1);
      const result = await route.handler(request);
      if (result === undefined) continue;
      if (result instanceof Error) throw result;
      return result.response && result.send ? result.response : result;
    }
    throw new TypeError('Offline: no route for ' + request.method + ' ' + request.url);
  }

  class FormData {
    constructor() { this._entries = []; }
    append(name, value) { this._entries.push([String(name), value]); }
    set(name, value) { this.delete(name); this.append(name, value); }
    delete(name) { this._entries = this._entries.filter(([key]) => key !== name); }
    get(name) { return this._entries.find(([key]) => key === name)?.[1] ?? null; }
    getAll(name) { return this._entries.filter(([key]) => key === name).map(([, value]) => value); }
    has(name) { return this._entries.some(([key]) => key === name); }
    entries() { return this._entries[Symbol.iterator](); }
    [Symbol.iterator]() { return this.entries(); }
  }
  class DataTransfer {
    constructor() {
      const files = fileList([]);
      this.files = files;
      this.items = {add: file => { files.push(file); }};
      this.types = ['Files'];
    }
  }
  const sources = [];
  class EventSource {
    constructor(url) { this.url = String(url); this.readyState = 0; this._listeners = {}; this.onerror = null; sources.push(this); }
    addEventListener(type, callback) { (this._listeners[type] ||= []).push(callback); }
    emit(type, data) {
      this.readyState = 1;
      for (const callback of this._listeners[type] || []) callback({type, data: typeof data === 'string' ? data : JSON.stringify(data), lastEventId: ''});
    }
    fail(closed = false) { this.readyState = closed ? 2 : 0; this.onerror?.({type: 'error'}); }
    close() { this.readyState = 2; this.closed = true; }
  }
  const storage = (initial = {}) => {
    const values = new Map(Object.entries(initial).map(([key, value]) => [key, String(value)]));
    return {getItem: key => values.has(String(key)) ? values.get(String(key)) : null, setItem: (key, value) => values.set(String(key), String(value)),
      removeItem: key => values.delete(String(key)), clear: () => values.clear(), get length() { return values.size; }};
  };
  const media = {desktop: true, reducedMotion: false, finePointer: true, ...(options.media || {})};
  const queries = {'(min-width: 992px)': () => media.desktop, '(prefers-reduced-motion: reduce)': () => media.reducedMotion,
    '(pointer: fine)': () => media.finePointer};
  const clipboard = [];
  const path = options.path || '/chat/';
  const location = {origin: 'http://testserver', pathname: path, search: '', hash: '', reloads: 0,
    get href() { return this.origin + this.pathname + this.search; }, reload() { this.reloads++; }, assign(url) { this.pathname = String(url); }};
  const history = {entries: [], state: null,
    replaceState(state, _, url) { this.state = state; this.entries.push({type: 'replace', url: String(url)}); location.pathname = String(url); },
    pushState(state, _, url) { this.state = state; this.entries.push({type: 'push', url: String(url)}); location.pathname = String(url); }};

  const events = new Target();
  const document = new Document(window);
  const define = (name, value) => Object.defineProperty(window, name, {value, writable: true, configurable: true, enumerable: true});
  Object.assign(events, {});
  const globals = {
    window, self: window, document, location, history, navigator: {userAgent: 'offline-browser', language: 'es-ES', clipboard: {writeText: async value => { clipboard.push(String(value)); }}},
    localStorage: storage(options.storage), sessionStorage: storage(), innerWidth: options.width || 1440, innerHeight: options.height || 900,
    matchMedia: query => ({media: query, get matches() { return queries[query] ? queries[query]() : false; },
      addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}}),
    setTimeout: (callback, delay, ...args) => setTimer(callback, delay, args, null),
    setInterval: (callback, delay, ...args) => setTimer(callback, delay, args, Math.max(1, Number(delay) || 0)),
    clearTimeout: id => { timers.delete(id); }, clearInterval: id => { timers.delete(id); },
    requestAnimationFrame: callback => setTimer(callback, 16, [now + 16], null), cancelAnimationFrame: id => { timers.delete(id); },
    fetch, FormData, DataTransfer, EventSource, Event, CustomEvent, MouseEvent, KeyboardEvent, FocusEvent, DragEvent,
    Node, Element, HTMLElement: Element, Text, Document,
    addEventListener: events.addEventListener.bind(events), removeEventListener: events.removeEventListener.bind(events),
    dispatchEvent: events.dispatchEvent.bind(events), scrollTo() {}, getComputedStyle: () => styleOf(),
    navigations: [], scrolledIntoView: [], events,
    // Test helpers.
    assert, net, sources, media, clipboard, flush, tick, text, timers,
    visible: node => text(node, {hidden: false}),
    $: (selector, root = document) => root.querySelector(selector),
    $$: (selector, root = document) => [...root.querySelectorAll(selector)],
    click: async target => { (typeof target === 'string' ? document.querySelector(target) : target).click(); await flush(); },
    typeInto: async (target, value) => {
      target.value = value;
      target.dispatchEvent(new Event('input', {bubbles: true}));
      await flush();
    },
    press: async (target, key, init = {}) => {
      const event = new KeyboardEvent('keydown', {key, bubbles: true, cancelable: true, ...init});
      target.dispatchEvent(event);
      await flush();
      return event;
    },
    file: (name, size = 12, type = '') => ({name, size, type, lastModified: 0}),
  };
  for (const [name, value] of Object.entries(globals)) define(name, value);
  for (const name of ['IntersectionObserver', 'ResizeObserver']) if (!(options.observers || []).includes(name)) define(name, undefined);
  return document;
}

function load(document, tree) {
  const make = node => {
    if (typeof node === 'string') return document.createTextNode(node);
    const [tag, attributes, children] = node;
    const element = document.createElement(tag);
    for (const [name, value] of Object.entries(attributes)) element.setAttribute(name, value);
    for (const child of children) element.appendChild(make(child));
    return element;
  };
  const roots = tree ? tree[2].filter(node => typeof node !== 'string') : [];
  const html = roots.find(node => node[0] === 'html');
  const root = make(html || ['html', {lang: 'es'}, [['head', {}, []], ['body', {}, roots]]]);
  document.appendChild(root);
  if (!root.children.some(node => node.localName === 'head')) root.prepend(document.createElement('head'));
  if (!root.children.some(node => node.localName === 'body')) root.appendChild(document.createElement('body'));
}

async function main() {
  const input = JSON.parse(fs.readFileSync(0, 'utf8'));
  const rejections = [];
  process.on('unhandledRejection', error => { rejections.push(error); });
  const document = install(input.options || {});
  load(document, input.tree);
  for (const script of input.scripts) vm.runInThisContext(script.source, {filename: script.name});
  document.readyState = 'interactive';
  document.dispatchEvent(new Event('DOMContentLoaded', {bubbles: true}));
  document.readyState = 'complete';
  await globalThis.flush();
  const checks = vm.runInThisContext('(async () => {\n' + input.checks + '\n})', {filename: 'checks.js', lineOffset: -1});
  await checks();
  await globalThis.flush();
  if (rejections.length) throw rejections[0];
}

// Failing is the default: checks stuck on a promise that never settles let node
// exit with an empty event loop, and that must not count as a pass.
let finished = false;
process.exitCode = 1;
process.on('exit', () => {
  if (!finished) process.stderr.write('The checks did not finish: an awaited promise never settled.\n');
});
main().then(() => { finished = true; process.exitCode = 0; }, error => {
  finished = true;
  process.stderr.write(String(error?.stack || error) + '\n');
  process.exitCode = 1;
});
