/*
 *
 * Algorithms (Updated)
 *
 */

const x16r = require('../../index').x16r;
const x16rv2 = require('../../index').x16rv2;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented x16r algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('f3bd8f00ace441b322c14a179396c0835087536a2d86b7fec062ab88beb0e9c5', 'hex');
    expect(x16r.apply(null, [start]).length).toBe(32);
    expect(x16r.apply(null, [start])).toStrictEqual(output);
  });

  // Deterministic
  test('Test implemented x16rv2 algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('f3bd8f00ace441b322c14a179396c0835087536a2d86b7fec062ab88beb0e9c5', 'hex');
    expect(x16rv2.apply(null, [start]).length).toBe(32);
    expect(x16rv2.apply(null, [start])).toStrictEqual(output);
  });
});
