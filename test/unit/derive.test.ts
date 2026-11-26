import { mnemonicToSeed } from '@mysten/sui/cryptography';
import { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { numberToBytesBE } from '@noble/curves/utils.js';
import { describe, expect, it } from 'vitest';

import {
	derivePrfKey,
	deriveSalt,
	OneTimeKeys,
	tweakPublicKey,
	tweakSecretKey,
} from '../../src/derive.js';
import { CHAIN, MNEMONIC, OTHER_CHAIN } from './helpers.js';

const Point = secp256k1.Point;
const N = Point.Fn.ORDER;

const keys = new OneTimeKeys({ mnemonic: MNEMONIC, chainIdentifier: CHAIN });

describe('OneTimeKeys', () => {
	it('uses the standard secp256k1 key of the mnemonic as the account', () => {
		const base = Secp256k1Keypair.deriveKeypair(MNEMONIC);
		expect(keys.account).toBe(base.toSuiAddress());
		expect(keys.baseKeypair().getPublicKey().toRawBytes()).toEqual(
			base.getPublicKey().toRawBytes(),
		);
	});

	it('derives the same public key from the secret key and from the public key alone', () => {
		const basePublicKey = keys.baseKeypair().getPublicKey().toRawBytes();
		for (let index = 0; index < 8; index++) {
			const fromSecret = keys.keypair(index).getPublicKey();
			expect(keys.publicKey(index).toRawBytes()).toEqual(fromSecret.toRawBytes());
			expect(keys.address(index)).toBe(fromSecret.toSuiAddress());

			// pk_i = pk_base + s_i·G, checked against noble directly.
			const expected = Point.fromBytes(basePublicKey).add(Point.BASE.multiply(keys.salt(index)));
			expect(Point.fromBytes(fromSecret.toRawBytes()).equals(expected)).toBe(true);
		}
	});

	it('signs with the one-time key', async () => {
		const bytes = new Uint8Array([1, 2, 3]);
		const { signature } = await keys.keypair(3).signTransaction(bytes);
		expect(await keys.publicKey(3).verifyTransaction(bytes, signature)).toBe(true);
		await expect(keys.publicKey(4).verifyTransaction(bytes, signature)).rejects.toThrow(
			/does not match/,
		);
	});

	it('gives every index its own address, none of them the account', () => {
		const addresses = Array.from({ length: 200 }, (_, index) => keys.address(index));
		expect(new Set(addresses).size).toBe(addresses.length);
		expect(addresses).not.toContain(keys.account);
	});

	it('separates chains, accounts and mnemonics', () => {
		const otherChain = new OneTimeKeys({ mnemonic: MNEMONIC, chainIdentifier: OTHER_CHAIN });
		const otherPath = new OneTimeKeys({
			mnemonic: MNEMONIC,
			chainIdentifier: CHAIN,
			path: "m/54'/784'/1'/0/0",
		});
		const otherMnemonic = new OneTimeKeys({
			mnemonic: 'legal winner thank year wave sausage worth useful legal winner thank yellow',
			chainIdentifier: CHAIN,
		});

		// Same account on another chain: same base key, unrelated one-time keys.
		expect(otherChain.account).toBe(keys.account);
		expect(otherChain.salt(0)).not.toBe(keys.salt(0));
		expect(otherChain.address(0)).not.toBe(keys.address(0));

		// Another account of the same mnemonic shares the PRF key, but not the salts.
		expect(otherPath.account).not.toBe(keys.account);
		expect(otherPath.salt(0)).not.toBe(keys.salt(0));

		expect(otherMnemonic.salt(0)).not.toBe(keys.salt(0));
	});

	it('is pinned to known values', () => {
		expect({
			account: keys.account,
			address0: keys.address(0),
			address1: keys.address(1),
			salt0: keys.salt(0).toString(16),
		}).toMatchInlineSnapshot(`
			{
			  "account": "0xc61a7f1161020a717f852dca2e9bfc1ffe235145406dfbdccc16e6907c1f5403",
			  "address0": "0xf34e5a68c9a30c3ffd8193b32921b71da936db5de8af172d953c5f58fe7e54ea",
			  "address1": "0x8642f5ae1e2ddad9289b68bea94d2b8020aa68ca7b38148a5d9a1602b03e9bc0",
			  "salt0": "850d5972e3c1e3375379cfafe36c10eeaafbf893415ea3fe28697aaf5e5c7d07",
			}
		`);
	});

	it('rejects a chain identifier that is not a 32-byte digest', () => {
		expect(() => new OneTimeKeys({ mnemonic: MNEMONIC, chainIdentifier: '35834a8a' })).toThrow(
			/chain identifier/,
		);
	});
});

describe('derivation primitives', () => {
	const prfKey = derivePrfKey(mnemonicToSeed(MNEMONIC));

	it('derives the PRF key from the seed', () => {
		expect(prfKey).toHaveLength(64);
		expect(derivePrfKey(mnemonicToSeed(MNEMONIC))).toEqual(prfKey);
		expect(derivePrfKey(new Uint8Array(64))).not.toEqual(prfKey);
	});

	it('derives salts in [1, n-1], deterministically', () => {
		for (const index of [0, 1, 2, 2 ** 32, Number.MAX_SAFE_INTEGER]) {
			const salt = deriveSalt(prfKey, CHAIN, keys.account, index);
			expect(salt > 0n && salt < N).toBe(true);
			expect(deriveSalt(prfKey, CHAIN, keys.account, index)).toBe(salt);
		}
		expect(deriveSalt(prfKey, CHAIN, keys.account, 0)).not.toBe(
			deriveSalt(prfKey, CHAIN, keys.account, 1),
		);
	});

	it('rejects invalid indices', () => {
		for (const index of [-1, 0.5, Number.NaN, Number.MAX_SAFE_INTEGER + 1]) {
			expect(() => deriveSalt(prfKey, CHAIN, keys.account, index)).toThrow(/index/);
		}
	});

	it('adds the salt modulo the group order', () => {
		expect(tweakSecretKey(numberToBytesBE(N - 1n, 32), 2n)).toEqual(numberToBytesBE(1n, 32));
		expect(() => tweakSecretKey(numberToBytesBE(N - 1n, 32), 1n)).toThrow(/zero/);

		const generator = Point.BASE.toBytes(true);
		expect(tweakPublicKey(generator, 1n)).toEqual(Point.BASE.multiply(2n).toBytes(true));
		expect(() => tweakPublicKey(generator, N - 1n)).toThrow(/infinity/);
	});
});
