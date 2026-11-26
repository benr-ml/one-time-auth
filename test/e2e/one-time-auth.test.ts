import type { SuiClientTypes } from '@mysten/sui/client';
import { parseSerializedSignature } from '@mysten/sui/cryptography';
import type { Signer } from '@mysten/sui/cryptography';
import { requestSuiFromFaucetV2 } from '@mysten/sui/faucet';
import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';
import { generateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import { beforeAll, describe, expect, it } from 'vitest';

import {
	NotEnrolledError,
	OneTimeAuth,
	OneTimeKeys,
	RotationCheckError,
	SimulationFailedError,
} from '../../src/index.js';
import { createClient, faucetHost } from './network.js';

const RECIPIENT = normalizeSuiAddress('0x0e4e');
const client = createClient();

type Result = SuiClientTypes.TransactionResult<{ transaction: true; effects: true }>;

async function newAccount() {
	const mnemonic = generateMnemonic(wordlist);
	const signer = await OneTimeAuth.fromMnemonic(mnemonic, { client });
	const { chainIdentifier } = await client.core.getChainIdentifier();
	const keys = new OneTimeKeys({ mnemonic, chainIdentifier });

	await requestSuiFromFaucetV2({ host: faucetHost, recipient: signer.account });
	for (let attempt = 0; ; attempt++) {
		const { balance } = await client.core.getBalance({ owner: signer.account });
		if (BigInt(balance.balance) > 0n) break;
		if (attempt > 60) throw new Error('The faucet did not fund the account');
		await new Promise((resolve) => setTimeout(resolve, 500));
	}
	return { mnemonic, signer, keys };
}

/** A small payment out of the gas coin. */
function payment(amount: bigint | number = 1_000) {
	const tx = new Transaction();
	const [coin] = tx.splitCoins(tx.gas, [tx.pure.u64(amount)]);
	tx.transferObjects([coin], tx.pure.address(RECIPIENT));
	return tx;
}

/**
 * A payment of more than the account holds, with its gas fully specified. With nothing left to
 * resolve, building does not simulate it, so only OneTimeAuth stands between it and a signature.
 */
async function overdraft(owner: string) {
	const tx = payment(2n ** 62n);
	const [{ referenceGasPrice }, { objects }] = await Promise.all([
		client.core.getReferenceGasPrice(),
		client.core.listCoins({ owner }),
	]);
	tx.setGasPrice(BigInt(referenceGasPrice));
	tx.setGasBudget(50_000_000);
	tx.setGasPayment(objects.map(({ objectId, version, digest }) => ({ objectId, version, digest })));
	return tx;
}

async function aliasesOf(address: string) {
	const { addressAliases } = await client.core.getAddressAliases({ address });
	return addressAliases.aliases;
}

function signerOf(result: Result): Uint8Array {
	const [signature] = (result.Transaction ?? result.FailedTransaction).signatures;
	const parsed = parseSerializedSignature(signature);
	if (parsed.signatureScheme !== 'Secp256k1') {
		throw new Error(`Unexpected signature scheme ${parsed.signatureScheme}`);
	}
	return parsed.publicKey;
}

/** Sends a transaction for `sender` signed by an arbitrary key, bypassing OneTimeAuth. */
async function executeAs(sender: string, key: Signer, tx: Transaction): Promise<Result> {
	tx.setSender(sender);
	const bytes = await tx.build({ client, restrictedMoveCalls: [] });
	const { signature } = await key.signTransaction(bytes);
	const result = await client.core.executeTransaction({
		transaction: bytes,
		signatures: [signature],
		include: { transaction: true, effects: true },
	});
	await client.core.waitForTransaction({ result });
	return result;
}

describe('OneTimeAuth', () => {
	let mnemonic: string;
	let signer: OneTimeAuth;
	let keys: OneTimeKeys;
	let account: string;

	beforeAll(async () => {
		({ mnemonic, signer, keys } = await newAccount());
		account = signer.account;
	});

	it('starts out not enrolled', async () => {
		expect(await signer.sync()).toMatchObject({ status: 'not-enrolled', enabled: false });
		await expect(signer.signAndExecuteTransaction({ transaction: payment() })).rejects.toThrow(
			NotEnrolledError,
		);
	});

	it('enrolls: the alias becomes the first one-time key', async () => {
		expect(await signer.enroll()).toMatchObject({ status: 'active', index: 0 });
		expect(await aliasesOf(account)).toEqual([keys.address(0)]);
		await expect(signer.enroll()).rejects.toThrow(/already enrolled/);
	});

	it('locks out the base key', async () => {
		await expect(executeAs(account, keys.baseKeypair(), payment())).rejects.toThrow(
			/Required Signature from .* is absent/,
		);
	});

	it('signs every transaction with a fresh key and rotates to the next', async () => {
		for (let index = 0; index < 3; index++) {
			const result = await signer.signAndExecuteTransaction({ transaction: payment() });
			expect(result.$kind).toBe('Transaction');
			expect(signerOf(result)).toEqual(keys.publicKey(index).toRawBytes());
			expect(result.Transaction!.transaction.sender).toBe(account);
			expect(await aliasesOf(account)).toEqual([keys.address(index + 1)]);
			expect(signer.state).toMatchObject({ status: 'active', index: index + 1 });
			expect(signer.getPublicKey().toSuiAddress()).toBe(keys.address(index + 1));
		}
		expect(await signer.sync()).toMatchObject({ index: 3 });
	});

	it('rejects a key that was already used', async () => {
		const state = await signer.sync();
		if (state.status !== 'active') throw new Error('expected an active account');

		const replay = payment();
		replay.moveCall({
			target: '0x2::address_alias::replace_all',
			arguments: [
				replay.object(state.aliasObjectId),
				replay.pure.vector('address', [keys.address(1)]),
			],
		});
		await expect(executeAs(account, keys.keypair(1), replay)).rejects.toThrow(
			/Required Signature from .* is absent/,
		);
		expect(await aliasesOf(account)).toEqual([keys.address(3)]);
	});

	it('recovers the index from the mnemonic alone', async () => {
		const recovered = await OneTimeAuth.fromMnemonic(mnemonic, { client });
		expect(await recovered.sync()).toMatchObject({ status: 'active', index: 3 });

		const result = await recovered.signAndExecuteTransaction({ transaction: payment() });
		expect(signerOf(result)).toEqual(keys.publicKey(3).toRawBytes());

		// The first instance notices that the account moved on without it.
		expect(await signer.sync()).toMatchObject({ index: 4 });
	});

	it('does not sign a transaction that would fail', async () => {
		// Left to the client to resolve, the transaction already fails to build.
		await expect(
			signer.signAndExecuteTransaction({ transaction: payment(2n ** 62n) }),
		).rejects.toThrow(/InsufficientCoinBalance/);
		// Fully resolved, it builds, and OneTimeAuth's own simulation stops it.
		await expect(
			signer.signAndExecuteTransaction({ transaction: await overdraft(account) }),
		).rejects.toThrow(SimulationFailedError);

		expect(await aliasesOf(account)).toEqual([keys.address(4)]);
		expect(await signer.sync()).toMatchObject({ index: 4 });
	});

	it('rotates out a key that a failed transaction revealed', async () => {
		const result = await signer.signAndExecuteTransaction({
			transaction: await overdraft(account),
			skipSimulation: true,
		});
		expect(result.$kind).toBe('FailedTransaction');
		expect(signerOf(result)).toEqual(keys.publicKey(4).toRawBytes());

		// The failed transaction reverted its own rotation; the rescue rotation moved on.
		expect(await aliasesOf(account)).toEqual([keys.address(5)]);
		expect(await signer.sync()).toMatchObject({ index: 5 });

		const next = await signer.signAndExecuteTransaction({ transaction: payment() });
		expect(next.$kind).toBe('Transaction');
		expect(signerOf(next)).toEqual(keys.publicKey(5).toRawBytes());
	});

	it('rotates on request', async () => {
		expect(await signer.rotate()).toMatchObject({ index: 7 });
		expect(await aliasesOf(account)).toEqual([keys.address(7)]);
	});

	it('signs prepared bytes, and nothing else', async () => {
		const bare = payment();
		bare.setSender(account);
		await expect(signer.signTransaction(await bare.build({ client }))).rejects.toThrow(
			RotationCheckError,
		);
		await expect(signer.signPersonalMessage()).rejects.toThrow(/personal messages/);

		const prepared = await signer.prepare(payment());
		const bytes = await prepared.build({ client, restrictedMoveCalls: [] });
		const { signature } = await signer.signTransaction(bytes);
		const result = await client.core.executeTransaction({
			transaction: bytes,
			signatures: [signature],
			include: { transaction: true, effects: true },
		});
		await client.core.waitForTransaction({ result });
		expect(result.$kind).toBe('Transaction');
		expect(await signer.sync()).toMatchObject({ index: 8 });
	});

	it('works as the signer of client.core.signAndExecuteTransaction', async () => {
		// The SDK blocks address_alias calls unless the client allows them.
		const permissive = createClient({ restrictedMoveCalls: [] });
		const result = await permissive.core.signAndExecuteTransaction({
			transaction: await signer.prepare(payment()),
			signer,
			include: { transaction: true, effects: true },
		});
		await client.core.waitForTransaction({ result });
		expect(result.$kind).toBe('Transaction');
		expect(signerOf(result)).toEqual(keys.publicKey(8).toRawBytes());
		expect(await signer.sync()).toMatchObject({ index: 9 });
	});

	it('unenrolls, and re-enrolls only above the last index', async () => {
		expect(await signer.unenroll({ to: account })).toMatchObject({ lastIndex: 9 });
		expect(await aliasesOf(account)).toEqual([account]);
		expect(await signer.sync()).toMatchObject({ status: 'not-enrolled', enabled: true });

		const result = await executeAs(account, keys.baseKeypair(), payment());
		expect(result.$kind).toBe('Transaction');

		await expect(signer.enroll()).rejects.toThrow(/startIndex/);
		expect(await signer.enroll({ startIndex: 10 })).toMatchObject({ status: 'active', index: 10 });
		expect(await aliasesOf(account)).toEqual([keys.address(10)]);

		const after = await signer.signAndExecuteTransaction({ transaction: payment() });
		expect(signerOf(after)).toEqual(keys.publicKey(10).toRawBytes());
	});
});

describe('enrollment', () => {
	it('resumes after the alias set was created but not yet replaced', async () => {
		const { signer, keys } = await newAccount();
		const enable = new Transaction();
		enable.moveCall({ target: '0x2::address_alias::enable', arguments: [enable.object('0xa')] });
		await executeAs(signer.account, keys.baseKeypair(), enable);
		expect(await signer.sync()).toMatchObject({ status: 'not-enrolled', enabled: true });

		expect(await signer.enroll()).toMatchObject({ status: 'active', index: 0 });
		expect(await aliasesOf(signer.account)).toEqual([keys.address(0)]);
	});
});
