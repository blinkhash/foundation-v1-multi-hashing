/*
 *
 * Algorithms (Updated)
 *
 */

const minotaur = require('../../index').minotaur;
const minotaurx = require('../../index').minotaurx;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Deterministic
  test('Test implemented minotaur algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('8c747068ee59fd0144830613064ed2cbf06a5d4ffd5689b3d92b61fc6f0cb882', 'hex');
    expect(minotaur.apply(null, [start]).length).toBe(32);
    expect(minotaur.apply(null, [start])).toStrictEqual(output);
  });

  // Deterministic
  test('Test implemented minotaurx algorithm', () => {
    const start = Buffer.from('000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f');
    const output = Buffer.from('caf1a315977532632eaba2b9ac7ef357d7da1d0bf945013539e2ef92ebac89e4', 'hex');
    expect(minotaurx.apply(null, [start]).length).toBe(32);
    expect(minotaurx.apply(null, [start])).toStrictEqual(output);
  });
});
