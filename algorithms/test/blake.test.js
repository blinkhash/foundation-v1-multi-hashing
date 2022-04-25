/*
 *
 * Algorithms (Updated)
 *
 */

const blake = require('../../index').blake;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented blake algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('333ee53bcaa24da99c4e4cad0f1cfb3411193abbd8323e8f4ea7231811cb7d55', 'hex');
    expect(blake.apply(null, [start]).length).toBe(32);
    expect(blake.apply(null, [start])).toStrictEqual(output);
  });
});
