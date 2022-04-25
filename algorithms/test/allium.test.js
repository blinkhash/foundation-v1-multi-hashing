/*
 *
 * Algorithms (Updated)
 *
 */

const allium = require('../../index').allium;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented allium algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const main = Buffer.from('affb18b37144a5829c610c249b8f2b165aabcc27eeb39c4f3b4d07c0bb431bcc', 'hex');
    const output = Buffer.from('29924a95863303614fd5ad453ad3adcfceea74006d3582b0fe1bdd4e018c54c5', 'hex');
    expect(allium.apply(null, [start, main]).length).toBe(32);
    expect(allium.apply(null, [start, main])).toStrictEqual(output);
  });
});
