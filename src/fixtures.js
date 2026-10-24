export function securityFixture() {
  const event = (id, seconds, type, extra = {}) => ({ id, ts: `2026-10-24T10:00:${String(seconds).padStart(2, '0')}Z`, host: 'lab-win-1', user: 'synthetic-user', platform: 'windows', type, ...extra });
  const events = [event('failure-1', 1, 'login_failure'), event('failure-2', 10, 'login_failure'),
    event('failure-3', 20, 'login_failure'), event('benign-login', 25, 'login_success'),
    event('encoded', 30, 'process', { command: 'powershell.exe -EncodedCommand U1lOVEhFVElD' }),
    event('normal-process', 31, 'process', { command: 'powershell.exe Get-Date' }),
    event('privilege', 40, 'role_change', { platform: 'linux', host: 'lab-linux-1', role: 'sudo', action: 'grant' }),
    event('benign-role', 45, 'role_change', { platform: 'linux', role: 'viewer', action: 'grant' })];
  return { text: [...events].reverse().map(e => JSON.stringify(e)).join('\n') + '\nnot-json\n' + JSON.stringify(events[0]),
    labels: [{ rule: 'login-burst', eventId: 'failure-3' }, { rule: 'encoded-powershell', eventId: 'encoded' }, { rule: 'privilege-grant', eventId: 'privilege' }] };
}
export const scanFixture = {
  id: 'synthetic-scan-1', scanner: 'lab-json', source: 'fixture://synthetic-scan-1', observedAt: '2026-10-24T10:00:00Z',
  findings: [{ asset: 'lab-web-1', rule: 'missing-header', title: 'Synthetic missing security header', severity: 'medium', evidence: 'fixture://header-observation' }]
};
export function tradingFixture() {
  const e = (id, second, type, data = {}) => ({ id, ts: `2026-10-24T10:00:${String(second).padStart(2, '0')}Z`, type, ...data });
  return { config: { cashCents: 100000, maxPosition: 5, feePerUnit: 2, slippageCents: 1 }, events: [
    e('submit-buy', 0, 'submit', { orderId: 'buy-1', side: 'buy', quantity: 4, limitCents: 1001 }),
    e('fill-buy-1', 1, 'fill', { orderId: 'buy-1', quantity: 2, priceCents: 1000 }),
    e('disconnect', 2, 'connection', { connected: false }),
    e('fill-buy-2', 3, 'fill', { orderId: 'buy-1', quantity: 2, priceCents: 999 }),
    e('reconnect', 4, 'connection', { connected: true }),
    e('submit-sell', 5, 'submit', { orderId: 'sell-1', side: 'sell', quantity: 3, limitCents: 1099 }),
    e('fill-sell', 6, 'fill', { orderId: 'sell-1', quantity: 3, priceCents: 1100 }), e('kill', 7, 'kill')
  ] };
}
