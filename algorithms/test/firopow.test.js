/*
 *
 * Algorithms (Updated)
 *
 */

const firopow = require('../../index').firopow;

////////////////////////////////////////////////////////////////////////////////

describe('Test algorithm functionality', () => {

  // Kawpow Validation [1]
  test('Test implemented firopow algorithm [1]', () => {
    const header = Buffer.from('63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3', 'hex');
    const mixhash = Buffer.from('3414b7c3105a45426e56e6f4c800f4358334cc7df74d98141bb887185166436d', 'hex');
    const nonce = Buffer.from('9b95eb33003ba288', 'hex');
    const output = Buffer.alloc(32);
    expect(firopow.apply(null, [header, nonce, 262523, mixhash, output])).toBe(true);
  });

  // Kawpow Validation [2]
  test('Test implemented firopow algorithm [2]', () => {
    const header = Buffer.from('63543d3913fe56e6720c5e61e8d208d05582875822628f483279a3e8d9c9a8b3', 'hex');
    const mixhash = Buffer.from('3414b7c3105a45426e56e6f4c800f4358334cc7df74d98141bb887185166436d', 'hex');
    const nonce = Buffer.from('9b95eb33003ba288', 'hex');
    const output = Buffer.alloc(32);
    expect(firopow.apply(null, [header, nonce, 262524, mixhash, output])).toBe(false);
  });
});
