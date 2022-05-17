/*
 *
 * Algorithms (Updated)
 *
 */

const blake2s = require('../../index').blake2s;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented blake2s algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const main = Buffer.from('affb18b37144a5829c610c249b8f2b165aabcc27eeb39c4f3b4d07c0bb431bcc', 'hex');
    const output = Buffer.from('a5369384d0db609805d3782f64f64128b58c293a745084b53748833d5f7a0171', 'hex');
    expect(blake2s.apply(null, [start, main]).length).toBe(32);
    expect(blake2s.apply(null, [start, main])).toStrictEqual(output);
  });
});
