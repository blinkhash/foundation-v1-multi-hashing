/*
 *
 * Algorithms (Updated)
 *
 */

const fugue = require('../../index').fugue;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented fugue algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('10b761d0a8e010f8dbfc320f59df415d0bfe52ff2c6179c655c77315f6f02dd4', 'hex');
    expect(fugue.apply(null, [start]).length).toBe(32);
    expect(fugue.apply(null, [start])).toStrictEqual(output);
  });
});
