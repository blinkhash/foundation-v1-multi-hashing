/*
 *
 * Algorithms (Updated)
 *
 */

const nist5 = require('../../index').nist5;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented nist5 algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('1bc1a908ccdc3ca21241162a733e792ef5f6ef705ed2c988863d16313fc12680', 'hex');
    expect(nist5.apply(null, [start]).length).toBe(32);
    expect(nist5.apply(null, [start])).toStrictEqual(output);
  });
});
