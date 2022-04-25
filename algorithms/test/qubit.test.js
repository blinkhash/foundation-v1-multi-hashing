/*
 *
 * Algorithms (Updated)
 *
 */

const qubit = require('../../index').qubit;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented qubit algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('dcd2123c2a5750fab43f78f9a5834c5ef20acda10c0b9de3035b91a51a3408bb', 'hex');
    expect(qubit.apply(null, [start]).length).toBe(32);
    expect(qubit.apply(null, [start])).toStrictEqual(output);
  });
});
