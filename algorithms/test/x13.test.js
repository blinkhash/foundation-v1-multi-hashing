/*
 *
 * Algorithms (Updated)
 *
 */

const x13 = require('../../index').x13;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented x13 algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('bb638d59545d0be7d976862a1d90cc38149f32c83f46f4e6e0e01f70190dd168', 'hex');
    expect(x13.apply(null, [start]).length).toBe(32);
    expect(x13.apply(null, [start])).toStrictEqual(output);
  });
});
