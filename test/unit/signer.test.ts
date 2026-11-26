import type { ClientWithCoreApi } from '@mysten/sui/client';
import { parseSerializedSignature } from '@mysten/sui/cryptography';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';
import { describe, expect, it, vi } from 'vitest';

import { addRotation } from '../../src/alias.js';
import { OneTimeKeys } from '../../src/derive.js';
import { NotEnrolledError, RotationCheckError, UnknownAliasError } from '../../src/errors.js';
import { OneTimeAuth } from '../../src/one-time-auth.js';
import type { OneTimeAuthOptions } from '../../src/one-time-auth.js';
import { addResolvedRotation, ALIAS_OBJECT, buildOffline, CHAIN, MNEMONIC } from './helpers.js';

const keys = new OneTimeKeys({ mnemonic: MNEMONIC, chainIdentifier: CHAIN });

/** A client that only knows the alias set of the account, and its alias object. */
function fakeClient(chain: { aliases: string[]; enabled?: boolean; version?: string }) {
	const core = {
		getChainIdentifier: vi.fn(async () => ({ chainIdentifier: CHAIN })),
		getAddressAliases: vi.fn(async ({ address }: { address: string }) => ({
			addressAliases: {
				address,
				enabled: chain.enabled ?? true,
				aliases: chain.aliases,
				objectId: ALIAS_OBJECT,
			},
		})),
		getObject: vi.fn(async () => ({
			object: {
				objectId: ALIAS_OBJECT,
				version: chain.version ?? '10',
				owner: {
					$kind: 'ConsensusAddressOwner',
					ConsensusAddressOwner: { startVersion: '10', owner: keys.account },
				},
			},
		})),
		executeTransaction: vi.fn(async () => {
			throw new Error('The fake client does not execute transactions');
		}),
	};
	return { client: { core } as unknown as ClientWithCoreApi, core };
}

function signerAt(index: number, options: Partial<OneTimeAuthOptions> = {}) {
	const fake = fakeClient({ aliases: [keys.address(index)] });
	return { ...fake, signer: new OneTimeAuth(keys, { client: fake.client, ...options }) };
}

describe('sync', () => {
	it('fetches the chain identifier when created from a mnemonic', async () => {
		const { client } = fakeClient({ aliases: [keys.address(2)] });
		const signer = await OneTimeAuth.fromMnemonic(MNEMONIC, { client });
		expect(signer.account).toBe(keys.account);
		expect(await signer.sync()).toMatchObject({ status: 'active', index: 2 });
	});

	it('reports an account that is its own alias as not enrolled', async () => {
		for (const enabled of [false, true]) {
			const { client } = fakeClient({ aliases: [keys.account], enabled });
			const signer = new OneTimeAuth(keys, { client });
			expect(await signer.sync()).toEqual({
				status: 'not-enrolled',
				aliasObjectId: ALIAS_OBJECT,
				enabled,
			});
			await expect(signer.signTransaction(new Uint8Array())).rejects.toThrow(NotEnrolledError);
			await expect(signer.prepare(new Transaction())).rejects.toThrow(NotEnrolledError);
		}
	});

	it('finds the index by scanning forward from the hint', async () => {
		const onIndexChange = vi.fn();
		const { signer } = signerAt(37, { onIndexChange });
		expect(await signer.sync()).toEqual({
			status: 'active',
			aliasObjectId: ALIAS_OBJECT,
			index: 37,
			alias: keys.address(37),
		});
		expect(onIndexChange).toHaveBeenCalledExactlyOnceWith(37);

		await signer.sync();
		expect(onIndexChange).toHaveBeenCalledOnce();
	});

	it('finds the index at, just after and before the hint', async () => {
		for (const [index, indexHint] of [
			[5, 5],
			[6, 5],
			[4, 5],
			[3, 500],
		]) {
			const { signer } = signerAt(index, { indexHint, scanLimit: 10 });
			expect(await signer.sync()).toMatchObject({ index });
		}
	});

	it('rejects an alias that is not one of its keys', async () => {
		const stranger = normalizeSuiAddress('0x57a4');
		const { client } = fakeClient({ aliases: [stranger] });
		const signer = new OneTimeAuth(keys, { client, scanLimit: 20 });
		await expect(signer.sync()).rejects.toThrow(UnknownAliasError);

		// A key that exists, but beyond the scan limit.
		await expect(signerAt(30, { scanLimit: 20 }).signer.sync()).rejects.toThrow(UnknownAliasError);
	});

	it('rejects an alias set with more than one alias', async () => {
		const { client } = fakeClient({ aliases: [keys.address(0), keys.account] });
		await expect(new OneTimeAuth(keys, { client }).sync()).rejects.toThrow(/2 aliases/);
	});
});

describe('signer identity', () => {
	it('identifies as the account and keeps its current public key private', async () => {
		const { signer } = signerAt(4);
		await signer.sync();
		expect(signer.toSuiAddress()).toBe(keys.account);
		expect(signer.getKeyScheme()).toBe('Secp256k1');
		expect(() => signer.getPublicKey()).toThrow(/does not expose/);
	});

	it('refuses to sign anything but a transaction', async () => {
		const { signer } = signerAt(0);
		const message = new Uint8Array([1, 2, 3]);
		await expect(signer.sign()).rejects.toThrow(/only signs transactions/);
		await expect(signer.signWithIntent()).rejects.toThrow(/only signs transactions/);
		await expect(signer.signPersonalMessage()).rejects.toThrow(/personal messages/);
		// The same through the base class signatures.
		await expect(
			(signer as unknown as { signPersonalMessage(m: Uint8Array): Promise<unknown> }).signPersonalMessage(
				message,
			),
		).rejects.toThrow(/personal messages/);
	});
});

describe('signTransaction', () => {
	it('signs a transaction that rotates to the next key, with the current key', async () => {
		const { signer } = signerAt(4);
		const tx = new Transaction();
		addResolvedRotation(tx, keys.address(5));
		const bytes = await buildOffline(tx, keys.account);

		const { signature } = await signer.signTransaction(bytes);
		const parsed = parseSerializedSignature(signature);
		if (parsed.signatureScheme !== 'Secp256k1') {
			throw new Error(`Unexpected signature scheme ${parsed.signatureScheme}`);
		}
		expect(parsed.publicKey).toEqual(keys.publicKey(4).toRawBytes());
		expect(await keys.publicKey(4).verifyTransaction(bytes, signature)).toBe(true);
	});

	it('refuses a transaction without the rotation', async () => {
		const { signer } = signerAt(4);
		const tx = new Transaction();
		tx.transferObjects([tx.splitCoins(tx.gas, [tx.pure.u64(1)])], tx.pure.address(keys.account));
		const bytes = await buildOffline(tx, keys.account);
		await expect(signer.signTransaction(bytes)).rejects.toThrow(RotationCheckError);
	});

	it('refuses a rotation to any key but the next', async () => {
		const { signer } = signerAt(4);
		for (const next of [keys.address(4), keys.address(6), keys.account]) {
			const tx = new Transaction();
			addResolvedRotation(tx, next);
			const bytes = await buildOffline(tx, keys.account);
			await expect(signer.signTransaction(bytes)).rejects.toThrow(/expected next key/);
		}
	});

	it('refuses a transaction from another sender', async () => {
		const { signer } = signerAt(4);
		const tx = new Transaction();
		addResolvedRotation(tx, keys.address(5));
		const bytes = await buildOffline(tx, normalizeSuiAddress('0x07e4'));
		await expect(signer.signTransaction(bytes)).rejects.toThrow(/sender/);
	});
});

describe('prepare', () => {
	const aliasCalls = (tx: Transaction) =>
		tx.getData().commands.filter((command) => command.MoveCall?.module === 'address_alias');

	it('sets the sender and appends the rotation once', async () => {
		const { signer } = signerAt(4);
		const tx = new Transaction();
		tx.transferObjects([tx.splitCoins(tx.gas, [tx.pure.u64(1)])], tx.pure.address(keys.account));

		expect(await signer.prepare(tx)).toBe(tx);
		expect(tx.getData().sender).toBe(keys.account);
		expect(aliasCalls(tx)).toHaveLength(1);
		expect(tx.getData().commands.at(-1)?.MoveCall?.function).toBe('replace_all');

		await signer.prepare(tx);
		expect(aliasCalls(tx)).toHaveLength(1);
	});

	it('rejects another sender', async () => {
		const { signer } = signerAt(4);
		const tx = new Transaction();
		tx.setSender(normalizeSuiAddress('0x07e4'));
		await expect(signer.prepare(tx)).rejects.toThrow(/sender/);
	});

	it('rejects a transaction that already changes the alias set differently', async () => {
		const { signer } = signerAt(4);
		const tx = new Transaction();
		addRotation(tx, ALIAS_OBJECT, keys.address(9));
		await expect(signer.prepare(tx)).rejects.toThrow(RotationCheckError);
	});
});

describe('enroll', () => {
	it('refuses an account that is already enrolled', async () => {
		const { signer, core } = signerAt(4);
		await expect(signer.enroll()).rejects.toThrow(/already enrolled, at index 4/);
		expect(core.executeTransaction).not.toHaveBeenCalled();
	});

	it('requires a start index when the alias set has been changed before', async () => {
		const { client, core } = fakeClient({ aliases: [keys.account], enabled: true, version: '42' });
		const signer = new OneTimeAuth(keys, { client });
		await expect(signer.enroll()).rejects.toThrow(/startIndex/);
		expect(core.executeTransaction).not.toHaveBeenCalled();
	});
});

describe('signAndExecuteTransaction', () => {
	it('only works through its own client', async () => {
		const { signer } = signerAt(4);
		const other = fakeClient({ aliases: [] }).client;
		await expect(
			signer.signAndExecuteTransaction({ transaction: new Transaction(), client: other }),
		).rejects.toThrow(/client it was created with/);
	});
});
