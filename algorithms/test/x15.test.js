/*
 *
 * Algorithms (Updated)
 *
 */

const x15 = require('../../index').x15;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented x15 algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('4c96c4733c3012eda472229214c71f63defa052e71ea3425d72d899822bc65df', 'hex');
    expect(x15.apply(null, [start]).length).toBe(32);
    expect(x15.apply(null, [start])).toStrictEqual(output);
  });
});
