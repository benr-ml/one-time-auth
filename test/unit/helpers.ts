import { Transaction } from '@mysten/sui/transactions';
import { normalizeSuiAddress, toBase58 } from '@mysten/sui/utils';

/** The BIP39 test mnemonic. Never use it for anything but tests. */
export const MNEMONIC =
	'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

export const CHAIN = toBase58(new Uint8Array(32).fill(1));
export const OTHER_CHAIN = toBase58(new Uint8Array(32).fill(2));

export const ALIAS_OBJECT = normalizeSuiAddress('0xa11a5');
export const OTHER_OBJECT = normalizeSuiAddress('0xbad');

/** Appends the rotation with a fully resolved alias object, so the transaction builds offline. */
export function addResolvedRotation(
	tx: Transaction,
	next: string,
	{ objectId = ALIAS_OBJECT, mutable = true, fn = 'replace_all', pkg = '0x2' } = {},
) {
	tx.moveCall({
		target: `${pkg}::address_alias::${fn}`,
		arguments: [
			tx.sharedObjectRef({ objectId, initialSharedVersion: 5, mutable }),
			tx.pure.vector('address', [next]),
		],
	});
}

/** Builds without a client: every input and all gas data must already be resolved. */
export async function buildOffline(tx: Transaction, sender: string): Promise<Uint8Array> {
	tx.setSender(sender);
	tx.setGasPrice(1000);
	tx.setGasBudget(10_000_000);
	tx.setGasPayment([
		{
			objectId: normalizeSuiAddress('0x6a5'),
			version: '1',
			digest: toBase58(new Uint8Array(32).fill(7)),
		},
	]);
	return tx.build({ restrictedMoveCalls: [] });
}

export async function builtData(
	tx: Transaction,
	sender: string,
): Promise<ReturnType<Transaction['getData']>> {
	return Transaction.from(await buildOffline(tx, sender)).getData();
}
