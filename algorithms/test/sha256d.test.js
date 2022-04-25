/*
 *
 * Algorithms (Updated)
 *
 */

const sha256d = require('../../index').sha256d;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented sha256d algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('dc83687981432eb309f7c96a51f8bd10cec4a4630f47fdca1c2768d34ba9031a', 'hex');
    expect(sha256d.apply(null, [start]).length).toBe(32);
    expect(sha256d.apply(null, [start])).toStrictEqual(output);
  });
});
