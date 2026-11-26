import { bcs } from '@mysten/sui/bcs';
import type { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';

import { RotationCheckError } from './errors.js';

const ALIAS_PACKAGE = normalizeSuiAddress('0x2');
const ALIAS_MODULE = 'address_alias';
/** The shared `0x2::address_alias::AddressAliasState`. */
const ALIAS_STATE_ID = '0xa';

type TransactionData = ReturnType<Transaction['getData']>;

export interface ExpectedRotation {
	/** The account whose alias set is rotated; must be the transaction sender. */
	sender: string;
	/** The account's `AddressAliases` object. */
	aliasObjectId: string;
	/** The single address the alias set must be replaced with. */
	next: string;
}

/** Appends `0x2::address_alias::enable`, which creates the sender's alias set. */
export function addEnable(tx: Transaction) {
	tx.moveCall({
		target: '0x2::address_alias::enable',
		arguments: [tx.object(ALIAS_STATE_ID)],
	});
}

/**
 * Appends `replace_all(aliases, [next])`: after it, only `next` can sign for the sender.
 *
 * With `startVersion` (the version at which the alias set was created) the input is fully
 * resolved, so the rotation itself never forces the transaction through a resolving client.
 */
export function addRotation(
	tx: Transaction,
	aliasObjectId: string,
	next: string,
	startVersion?: string,
) {
	const aliases =
		startVersion === undefined
			? tx.object(aliasObjectId)
			: tx.sharedObjectRef({
					objectId: aliasObjectId,
					initialSharedVersion: startVersion,
					mutable: true,
				});
	tx.moveCall({
		target: '0x2::address_alias::replace_all',
		arguments: [aliases, tx.pure.vector('address', [next])],
	});
}

function nextBytes(next: string): string {
	return bcs.vector(bcs.Address).serialize([next]).toBase64();
}

/**
 * Checks the `0x2::address_alias` calls of a transaction against the expected rotation.
 *
 * Returns `false` if the transaction has no such call and `true` if it has exactly the expected
 * one. Any other alias call throws: the alias set decides who controls the account, so nothing
 * but the expected rotation may touch it.
 *
 * `built` is for transactions parsed from their final bytes, where the alias object must be a
 * resolved, mutable consensus input. Without it the object may still be unresolved.
 */
export function checkRotation(
	data: TransactionData,
	expected: ExpectedRotation,
	{ built }: { built: boolean },
): boolean {
	const calls = data.commands.flatMap((command) => {
		const call = command.MoveCall;
		return call && normalizeSuiAddress(call.package) === ALIAS_PACKAGE && call.module === ALIAS_MODULE
			? [call]
			: [];
	});

	if (calls.length === 0) return false;
	if (calls.length > 1) {
		throw new RotationCheckError(
			`Transaction has ${calls.length} address_alias calls; only the key rotation is allowed`,
		);
	}

	const [call] = calls;
	if (call.function !== 'replace_all' || call.typeArguments.length !== 0) {
		throw new RotationCheckError(
			`Transaction calls address_alias::${call.function}; only the key rotation is allowed`,
		);
	}

	const [aliases, next] = call.arguments;
	if (call.arguments.length !== 2 || aliases.$kind !== 'Input' || next.$kind !== 'Input') {
		throw new RotationCheckError('The key rotation must take its arguments from inputs');
	}

	const aliasesInput = data.inputs[aliases.Input];
	const shared = aliasesInput?.Object?.SharedObject;
	const objectId =
		shared?.objectId ?? (built ? undefined : aliasesInput?.UnresolvedObject?.objectId);
	if (
		objectId === undefined ||
		normalizeSuiAddress(objectId) !== normalizeSuiAddress(expected.aliasObjectId) ||
		(shared !== undefined && !shared.mutable)
	) {
		throw new RotationCheckError("The key rotation does not target the account's alias set");
	}

	if (data.inputs[next.Input]?.Pure?.bytes !== nextBytes(expected.next)) {
		throw new RotationCheckError('The key rotation does not install the expected next key');
	}

	return true;
}

/**
 * Throws unless a built transaction is sent by `expected.sender` and carries exactly the expected
 * rotation. This is the last check before a one-time key signs.
 */
export function assertRotation(data: TransactionData, expected: ExpectedRotation) {
	if (!data.sender || normalizeSuiAddress(data.sender) !== normalizeSuiAddress(expected.sender)) {
		throw new RotationCheckError(
			`Transaction sender is ${data.sender ?? 'unset'}, expected ${expected.sender}`,
		);
	}
	if (!checkRotation(data, expected, { built: true })) {
		throw new RotationCheckError(
			'Transaction does not rotate the one-time key; add it with prepare() before building',
		);
	}
}
