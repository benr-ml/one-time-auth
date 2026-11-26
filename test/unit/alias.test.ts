import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';
import { describe, expect, it } from 'vitest';

import { addRotation, assertRotation, checkRotation } from '../../src/alias.js';
import { RotationCheckError } from '../../src/errors.js';
import { addResolvedRotation, ALIAS_OBJECT, builtData, OTHER_OBJECT } from './helpers.js';

const SENDER = normalizeSuiAddress('0x5e4de7');
const NEXT = normalizeSuiAddress('0x4e87');
const expected = { sender: SENDER, aliasObjectId: ALIAS_OBJECT, next: NEXT };

async function check(build: (tx: Transaction) => void, sender = SENDER) {
	const tx = new Transaction();
	build(tx);
	assertRotation(await builtData(tx, sender), expected);
}

describe('assertRotation', () => {
	it('accepts a transaction that only rotates', async () => {
		await check((tx) => addResolvedRotation(tx, NEXT));
	});

	it('accepts the rotation next to other commands, in any position', async () => {
		await check((tx) => {
			addResolvedRotation(tx, NEXT);
			const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1)]);
			tx.transferObjects([coin], tx.pure.address(SENDER));
		});
		await check((tx) => {
			const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1)]);
			tx.transferObjects([coin], tx.pure.address(SENDER));
			addResolvedRotation(tx, NEXT);
		});
	});

	it('rejects a transaction without a rotation', async () => {
		await expect(
			check((tx) => {
				const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(1)]);
				tx.transferObjects([coin], tx.pure.address(SENDER));
			}),
		).rejects.toThrow(/does not rotate/);
	});

	it('does not mistake another package or module for the rotation', async () => {
		await expect(check((tx) => addResolvedRotation(tx, NEXT, { pkg: '0x3' }))).rejects.toThrow(
			/does not rotate/,
		);
	});

	it('rejects a rotation to a different key', async () => {
		await expect(
			check((tx) => addResolvedRotation(tx, normalizeSuiAddress('0xe71'))),
		).rejects.toThrow(/expected next key/);
	});

	it('rejects a rotation that installs more than the next key', async () => {
		await expect(
			check((tx) =>
				tx.moveCall({
					target: '0x2::address_alias::replace_all',
					arguments: [
						tx.sharedObjectRef({ objectId: ALIAS_OBJECT, initialSharedVersion: 5, mutable: true }),
						tx.pure.vector('address', [NEXT, normalizeSuiAddress('0xe71')]),
					],
				}),
			),
		).rejects.toThrow(/expected next key/);
	});

	it('rejects a rotation of another alias set', async () => {
		await expect(
			check((tx) => addResolvedRotation(tx, NEXT, { objectId: OTHER_OBJECT })),
		).rejects.toThrow(/alias set/);
		await expect(check((tx) => addResolvedRotation(tx, NEXT, { mutable: false }))).rejects.toThrow(
			/alias set/,
		);
	});

	it('rejects any other address_alias call', async () => {
		await expect(check((tx) => addResolvedRotation(tx, NEXT, { fn: 'add' }))).rejects.toThrow(
			/address_alias::add/,
		);
		await expect(
			check((tx) => {
				addResolvedRotation(tx, NEXT);
				addResolvedRotation(tx, NEXT);
			}),
		).rejects.toThrow(/2 address_alias calls/);
		// A valid rotation does not excuse a second alias call.
		await expect(
			check((tx) => {
				addResolvedRotation(tx, NEXT);
				addResolvedRotation(tx, normalizeSuiAddress('0xe71'), { fn: 'add' });
			}),
		).rejects.toThrow(RotationCheckError);
	});

	it('rejects a next key computed inside the transaction', async () => {
		await expect(
			check((tx) =>
				tx.moveCall({
					target: '0x2::address_alias::replace_all',
					arguments: [
						tx.sharedObjectRef({ objectId: ALIAS_OBJECT, initialSharedVersion: 5, mutable: true }),
						tx.makeMoveVec({ type: 'address', elements: [tx.pure.address(NEXT)] }),
					],
				}),
			),
		).rejects.toThrow(/from inputs/);
	});

	it('rejects another sender', async () => {
		await expect(
			check((tx) => addResolvedRotation(tx, NEXT), normalizeSuiAddress('0x07e4')),
		).rejects.toThrow(/sender/);
	});
});

describe('checkRotation on an unbuilt transaction', () => {
	it('reports whether the rotation is there', () => {
		const tx = new Transaction();
		expect(checkRotation(tx.getData(), expected, { built: false })).toBe(false);
		addRotation(tx, ALIAS_OBJECT, NEXT);
		expect(checkRotation(tx.getData(), expected, { built: false })).toBe(true);
	});

	it('does not accept an unresolved alias object as built', () => {
		const tx = new Transaction();
		addRotation(tx, ALIAS_OBJECT, NEXT);
		expect(() => checkRotation(tx.getData(), expected, { built: true })).toThrow(/alias set/);
	});

	it('rejects a conflicting alias call', () => {
		const tx = new Transaction();
		addRotation(tx, ALIAS_OBJECT, normalizeSuiAddress('0xe71'));
		expect(() => checkRotation(tx.getData(), expected, { built: false })).toThrow(
			/expected next key/,
		);
	});
});
