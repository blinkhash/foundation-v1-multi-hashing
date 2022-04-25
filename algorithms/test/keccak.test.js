/*
 *
 * Algorithms (Updated)
 *
 */

const keccak = require('../../index').keccak;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic w/ Argument
  test('Test implemented keccak algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('976ce35ca29d5e4ce95f794fe13545580434dce2a7409c98d0888e9eeacd833a', 'hex');
    expect(keccak.apply(null, [start]).length).toBe(32);
    expect(keccak.apply(null, [start])).toStrictEqual(output);
  });
});
