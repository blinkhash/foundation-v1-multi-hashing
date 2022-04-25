/*
 *
 * Algorithms (Updated)
 *
 */

const groestl = require('../../index').groestl;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic w/ Argument
  test('Test implemented groestl algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('c444502e5a9f93f221950a9d392987570aa3a8e8cb837749ec33eafa140cf017', 'hex');
    expect(groestl.apply(null, [start]).length).toBe(32);
    expect(groestl.apply(null, [start])).toStrictEqual(output);
  });
});
