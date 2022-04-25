/*
 *
 * Algorithms (Updated)
 *
 */

const quark = require('../../index').quark;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented quark algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('c7b2305e079030ce11a87ca15bf497d378ffc8c2a3739965f544ba53f5c3799e', 'hex');
    expect(quark.apply(null, [start]).length).toBe(32);
    expect(quark.apply(null, [start])).toStrictEqual(output);
  });
});
