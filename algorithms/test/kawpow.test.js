/*
 *
 * Algorithms (Updated)
 *
 */

const kawpow = require('../../index').kawpow;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Kawpow Validation [1]
  test('Test implemented kawpow algorithm [1]', () => {
    const header = Buffer.from('63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3', 'hex');
    const mixhash = Buffer.from('89732e5ff8711c32558a308fc4b8ee77416038a70995670e3eb84cbdead2e337', 'hex');
    const nonce = Buffer.from('9b95eb33003ba288', 'hex');
    const output = Buffer.alloc(32);
    expect(kawpow.apply(null, [header, nonce, 262523, mixhash, output])).toBe(true);
  });

  // Kawpow Validation [2]
  test('Test implemented kawpow algorithm [2]', () => {
    const header = Buffer.from('63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3', 'hex');
    const mixhash = Buffer.from('89732e5ff8711c32558a308fc4b8ee77416038a70995670e3eb84cbdead2e337', 'hex');
    const nonce = Buffer.from('9b95eb33003ba288', 'hex');
    const output = Buffer.alloc(32);
    expect(kawpow.apply(null, [header, nonce, 262524, mixhash, output])).toBe(false);
  });

  // Kawpow Validation [3]
  test('Test implemented kawpow algorithm [3]', () => {
    const header = Buffer.from('99ba4af95948377c47b1a6befc3a337f7b033ef6031a0c6a5ad3e727219653bd', 'hex');
    const mixhash = Buffer.from('5edcb1e324144e076caa059478d9590e4ca1b29519be67b90d8020f039ee1b88', 'hex');
    const nonce = Buffer.from('cff52a0ab373f0b8', 'hex');
    const output = Buffer.alloc(32);
    expect(kawpow.apply(null, [header, nonce, 1973071, mixhash, output])).toBe(true);
  });

  // Kawpow Validation [4]
  test('Test implemented kawpow algorithm [4]', () => {
    const header = Buffer.from('99ba4af95948377c47b1a6befc3a337f7b033ef6031a0c6a5ad3e727219653bd', 'hex');
    const mixhash = Buffer.from('2472b66f1d2c94b122e4012f9f8f49c4211f81c06d9dd17196a4aa4f9449f3d6', 'hex');
    const nonce = Buffer.from('f8d08f6db373f0b8', 'hex');
    const output = Buffer.alloc(32);
    expect(kawpow.apply(null, [header, nonce, 1973071, mixhash, output])).toBe(false);
  });
});
