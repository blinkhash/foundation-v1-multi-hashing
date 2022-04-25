/*
 *
 * Algorithms (Updated)
 *
 */

const scrypt = require('../../index').scrypt;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented scrypt algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('8438235b4ae8f5ad897f9482545fdca3ebeabbc15bffd544cd35d2419976cb8d', 'hex');
    expect(scrypt.apply(null, [start, 1024, 1]).length).toBe(32);
    expect(scrypt.apply(null, [start, 1024, 1])).toStrictEqual(output);
  });
});
