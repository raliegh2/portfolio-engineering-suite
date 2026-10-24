import fs from 'node:fs/promises';
import path from 'node:path';
import { digest, requireText, utc } from './common.js';
function integer(n, name, minimum = 0) {
  if (!Number.isSafeInteger(n) || n < minimum) throw new Error('Invalid ' + name); return n;
}
export class PaperExchange {
  constructor({ cashCents = 100000, maxPosition = 10, feePerUnit = 2, slippageCents = 1 } = {}) {
    [cashCents, maxPosition, feePerUnit, slippageCents].forEach((n, i) => integer(n, 'config ' + i));
    this.state = { cashCents, position: 0, maxPosition, feePerUnit, slippageCents,
      connected: true, killed: false, orders: {}, seen: {}, ledger: [] };
  }
  apply(event) {
    requireText(event.id, 'event ID'); utc(event.ts);
    const fingerprint = digest(event), prior = this.state.seen[event.id];
    if (prior) { if (prior !== fingerprint) throw new Error('Conflicting event ID'); return { duplicate: true }; }
    if (['__proto__', 'prototype', 'constructor'].includes(event.id)) throw new Error('Invalid event ID');
    const state = structuredClone(this.state);
    const open = Object.values(state.orders).filter(o => o.remaining > 0 && o.status === 'open');
    if (event.type === 'connection') {
      if (typeof event.connected !== 'boolean') throw new Error('Invalid connection state');
      state.connected = event.connected;
    } else if (event.type === 'kill') {
      state.killed = true;
      for (const order of open) order.status = 'cancelled';
    } else if (event.type === 'submit') {
      if (state.killed || !state.connected) throw new Error('New orders disabled');
      requireText(event.orderId, 'order ID');
      if (Object.hasOwn(state.orders, event.orderId) || ['__proto__', 'constructor', 'prototype'].includes(event.orderId)) throw new Error('Duplicate or invalid order ID');
      if (!['buy', 'sell'].includes(event.side)) throw new Error('Invalid side');
      integer(event.quantity, 'quantity', 1); integer(event.limitCents, 'limit', 1);
      const buys = open.filter(o => o.side === 'buy');
      const sells = open.filter(o => o.side === 'sell');
      if (event.side === 'buy') {
        if (state.position + buys.reduce((n, o) => n + o.remaining, 0) + event.quantity > state.maxPosition) throw new Error('Exposure cap');
        const reserved = buys.reduce((n, o) => n + o.remaining * (o.limitCents + state.feePerUnit), 0);
        const required = integer(event.quantity * (event.limitCents + state.feePerUnit), 'order notional');
        if (reserved + required > state.cashCents) throw new Error('Insufficient available cash');
      } else if (event.quantity + sells.reduce((n, o) => n + o.remaining, 0) > state.position) throw new Error('Insufficient available position');
      state.orders[event.orderId] = { side: event.side, remaining: event.quantity, limitCents: event.limitCents, status: 'open' };
    } else if (event.type === 'fill') {
      const order = Object.hasOwn(state.orders, event.orderId) ? state.orders[event.orderId] : null;
      if (!order || order.status !== 'open') throw new Error('Unknown or closed order');
      integer(event.quantity, 'fill quantity', 1); integer(event.priceCents, 'fill price', 1);
      if (event.quantity > order.remaining) throw new Error('Overfill');
      const price = event.priceCents + (order.side === 'buy' ? state.slippageCents : -state.slippageCents);
      if (price < 1 || (order.side === 'buy' ? price > order.limitCents : price < order.limitCents)) throw new Error('Limit price violated');
      if (order.side === 'sell' && price < state.feePerUnit) throw new Error('Fee exceeds proceeds');
      const cashDelta = integer(event.quantity * (order.side === 'buy' ? price + state.feePerUnit : price - state.feePerUnit), 'cash delta');
      state.cashCents += order.side === 'buy' ? -cashDelta : cashDelta;
      state.position += order.side === 'buy' ? event.quantity : -event.quantity;
      order.remaining -= event.quantity; if (!order.remaining) order.status = 'filled';
    } else if (event.type === 'cancel') {
      const order = Object.hasOwn(state.orders, event.orderId) ? state.orders[event.orderId] : null;
      if (!order || order.status !== 'open') throw new Error('Unknown or closed order');
      order.status = 'cancelled';
    } else throw new Error('Unknown event type');
    integer(state.cashCents, 'cash balance'); integer(state.position, 'position');
    if (state.position > state.maxPosition) throw new Error('Position invariant');
    if (state.ledger.length && utc(event.ts) < utc(state.ledger.at(-1).ts)) throw new Error('Out-of-order event');
    state.seen[event.id] = fingerprint; state.ledger.push(structuredClone(event));
    this.state = state; return { duplicate: false };
  }
  snapshot() { return structuredClone(this.state); }
  hash() { return digest(this.state); }
  async save(file) {
    await fs.mkdir(path.dirname(file), { recursive: true });
    const temporary = file + '.tmp';
    await fs.writeFile(temporary, JSON.stringify({ schema: 1, digest: this.hash(), state: this.state }));
    await fs.rename(temporary, file);
  }
  static async load(file) {
    const checkpoint = JSON.parse(await fs.readFile(file, 'utf8'));
    if (checkpoint.schema !== 1 || digest(checkpoint.state) !== checkpoint.digest) throw new Error('Corrupt checkpoint');
    const state = checkpoint.state;
    const restored = new PaperExchange({ ...state });
    // Rebuild from events rather than trusting serialized balances, orders or deduplication maps.
    const initialCash = state.cashCents - state.ledger.reduce((delta, e) => {
      if (e.type !== 'fill') return delta;
      const submit = state.ledger.find(s => s.type === 'submit' && s.orderId === e.orderId);
      const p = e.priceCents + (submit.side === 'buy' ? state.slippageCents : -state.slippageCents);
      return delta + e.quantity * (submit.side === 'buy' ? -(p + state.feePerUnit) : p - state.feePerUnit);
    }, 0);
    restored.state.cashCents = integer(initialCash, 'initial cash');
    for (const event of state.ledger) restored.apply(event);
    if (restored.hash() !== checkpoint.digest) throw new Error('Checkpoint replay mismatch');
    return restored;
  }
}
