/*
 *
 * Algorithms (Updated)
 *
 */

const skein = require('../../index').skein;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented skein algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('33b951f9768163ad67e27b7cea6aa82a0153cf9055ddc0b419ccbdc33a32b12c', 'hex');
    expect(skein.apply(null, [start]).length).toBe(32);
    expect(skein.apply(null, [start])).toStrictEqual(output);
  });
});
