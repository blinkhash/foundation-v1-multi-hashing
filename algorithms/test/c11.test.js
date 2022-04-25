/*
 *
 * Algorithms (Updated)
 *
 */

const c11 = require('../../index').c11;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Non-Deterministic
  test('Test implemented c11 algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    expect(c11.apply(null, [start]).length).toBe(32);
  });
});
