import type { ClientWithCoreApi, SuiClientTypes } from '@mysten/sui/client';
import { Signer } from '@mysten/sui/cryptography';
import type { PublicKey, SignatureScheme, SignatureWithBytes } from '@mysten/sui/cryptography';
import type { Secp256k1Keypair } from '@mysten/sui/keypairs/secp256k1';
import { Transaction, TransactionDataBuilder } from '@mysten/sui/transactions';
import { normalizeSuiAddress } from '@mysten/sui/utils';

import { addEnable, addRotation, assertRotation, checkRotation } from './alias.js';
import { assertIndex, OneTimeKeys } from './derive.js';
import {
	describe,
	KeyExposedError,
	NotEnrolledError,
	OneTimeAuthError,
	RotationCheckError,
	SimulationFailedError,
	UnknownAliasError,
} from './errors.js';

/** Where the account stands on chain, as last read by `sync()`. */
export type OneTimeAuthState =
	| {
			/** The account is its own (only) alias: the base key signs for it. */
			status: 'not-enrolled';
			aliasObjectId: string;
			/** Whether the alias set object exists yet. */
			enabled: boolean;
	  }
	| ActiveState;

export interface ActiveState {
	/** The only alias is one-time key `index`. */
	status: 'active';
	aliasObjectId: string;
	index: number;
	alias: string;
}

export interface OneTimeAuthOptions {
	client: ClientWithCoreApi;
	/** BIP32 path of the base key. Defaults to `m/54'/784'/0'/0/0`. */
	path?: string;
	/**
	 * Where to start looking for the current key index. Purely an optimization: the index is
	 * always confirmed against the chain, and found by scanning when the hint is wrong.
	 */
	indexHint?: number;
	/** Called whenever the current index changes, e.g. to persist it as the next `indexHint`. */
	onIndexChange?: (index: number) => void;
	/** How many indices past the hint to try before giving up. Defaults to 100,000. */
	scanLimit?: number;
}

export interface SignAndExecuteOptions {
	transaction: Transaction;
	/** Accepted for `Signer` compatibility; must be the client the instance was created with. */
	client?: ClientWithCoreApi;
	/**
	 * Sign without simulating first. A transaction that then fails on chain reveals the current
	 * key without rotating it, which costs an extra rotation-only transaction.
	 */
	skipSimulation?: boolean;
}

type ExecuteResult = SuiClientTypes.TransactionResult<{ transaction: true; effects: true }>;

const DEFAULT_SCAN_LIMIT = 100_000;
/** A fullnode that has not caught up with our own last transaction is re-read this many times. */
const STALE_READ_RETRIES = 20;
const STALE_READ_DELAY_MS = 250;
/** Validators that have not yet applied the previous rotation reject the new key for a moment. */
const ALIAS_LAG_RETRIES = 4;
const ALIAS_LAG_DELAY_MS = 300;
/** After a submission error, how long to look for the transaction before treating it as lost. */
const LANDED_CHECK_TIMEOUT_MS = 5_000;

/**
 * A signer whose key is used once.
 *
 * The account is the Sui address of a mnemonic-derived secp256k1 key. Once enrolled, its alias
 * set holds a single address: the hash of one-time key `i`. Every transaction is signed by key
 * `i` and replaces the alias with the hash of key `i + 1`, so the chain never holds a public key
 * that can still sign.
 */
export class OneTimeAuth extends Signer {
	#client: ClientWithCoreApi;
	#keys: OneTimeKeys;
	#scanLimit: number;
	#onIndexChange?: (index: number) => void;

	/** Best guess of the current index. */
	#hint: number;
	/** The lowest index the chain can be at, from transactions this instance saw succeed. */
	#floor: number | undefined;
	#state: OneTimeAuthState | undefined;
	/** The version at which the alias set was created. It never changes. */
	#startVersion: string | undefined;
	#lock: Promise<unknown> = Promise.resolve();

	static async fromMnemonic(mnemonic: string, options: OneTimeAuthOptions): Promise<OneTimeAuth> {
		const { chainIdentifier } = await options.client.core.getChainIdentifier();
		return new OneTimeAuth(
			new OneTimeKeys({ mnemonic, path: options.path, chainIdentifier }),
			options,
		);
	}

	constructor(keys: OneTimeKeys, options: OneTimeAuthOptions) {
		super();
		const { indexHint = 0, scanLimit = DEFAULT_SCAN_LIMIT } = options;
		assertIndex(indexHint);
		this.#keys = keys;
		this.#client = options.client;
		this.#hint = indexHint;
		this.#scanLimit = scanLimit;
		this.#onIndexChange = options.onIndexChange;
	}

	/** The account address. It is the transaction sender and never changes. */
	get account(): string {
		return this.#keys.account;
	}

	/** The state as last read from the chain or left by this instance's own last transaction. */
	get state(): OneTimeAuthState | undefined {
		return this.#state;
	}

	/** The account address, not the address of the current one-time key. */
	override toSuiAddress(): string {
		return this.account;
	}

	getKeyScheme(): SignatureScheme {
		return 'Secp256k1';
	}

	/** The key that currently signs for the account, as far as this instance knows. */
	getPublicKey(): PublicKey {
		const state = this.#state;
		if (!state) {
			throw new OneTimeAuthError('State is unknown; call sync() first');
		}
		return state.status === 'active'
			? this.#keys.publicKey(state.index)
			: this.#keys.baseKeypair().getPublicKey();
	}

	/** Reads the alias set and works out which one-time key it holds. */
	sync(): Promise<OneTimeAuthState> {
		return this.#exclusive(() => this.#sync());
	}

	/**
	 * Hands the account over to one-time keys. The base key signs up to two transactions (creating
	 * the alias set, then replacing it with the first one-time key) and can no longer sign after
	 * the second.
	 *
	 * `startIndex` is required when the alias set has been changed before, because an index must
	 * never be used twice: pass one above every index used earlier.
	 */
	enroll({ startIndex }: { startIndex?: number } = {}): Promise<ActiveState> {
		return this.#exclusive(async () => {
			const state = await this.#sync();
			if (state.status === 'active') {
				throw new OneTimeAuthError(`Account is already enrolled, at index ${state.index}`);
			}

			const base = this.#keys.baseKeypair();
			if (!state.enabled) {
				const enable = new Transaction();
				addEnable(enable);
				await this.#executeWithBaseKey(enable, base);
			} else if (startIndex === undefined && (await this.#hasHistory(state.aliasObjectId))) {
				throw new OneTimeAuthError(
					'The alias set of this account has been changed before, so one-time keys may already have been used. Pass a startIndex above every index used earlier.',
				);
			}

			const index = startIndex ?? 0;
			assertIndex(index);
			const install = new Transaction();
			addRotation(
				install,
				state.aliasObjectId,
				this.#keys.address(index),
				await this.#aliasStartVersion(state.aliasObjectId),
			);
			await this.#executeWithBaseKey(install, base);

			this.#confirm(index, state.aliasObjectId);
			return this.#requireActive();
		});
	}

	/**
	 * Replaces the alias set with `to`, ending one-time keys for the account. Returns the last
	 * index used; a later `enroll` must start above it.
	 *
	 * Handing the account back to its own address is not a return to safety: the base public key
	 * has been public since enrollment.
	 */
	unenroll({ to }: { to: string }): Promise<{ digest: string; lastIndex: number }> {
		return this.#exclusive(async () => {
			const state = await this.#requireActive();
			const result = await this.#rotateTo(state, normalizeSuiAddress(to));
			this.#floor = undefined;
			this.#state = undefined;
			return { digest: result.Transaction.digest, lastIndex: state.index };
		});
	}

	/** Sends a transaction that does nothing but move to the next one-time key. */
	rotate(): Promise<{ digest: string; index: number }> {
		return this.#exclusive(async () => {
			const state = await this.#requireActive();
			const result = await this.#rotateTo(state, this.#keys.address(state.index + 1));
			this.#confirm(state.index + 1, state.aliasObjectId);
			return { digest: result.Transaction.digest, index: state.index + 1 };
		});
	}

	/**
	 * Sets the sender and appends the key rotation, so the transaction can be built and passed to
	 * `signTransaction`. Does nothing if the rotation is already there.
	 */
	prepare(transaction: Transaction): Promise<Transaction> {
		return this.#exclusive(async () => {
			const state = await this.#requireActive();
			await this.#attach(transaction, state, this.#keys.address(state.index + 1));
			return transaction;
		});
	}

	/**
	 * Signs built transaction bytes with the current one-time key, but only if the transaction is
	 * sent by the account and rotates to the next key.
	 */
	override signTransaction(bytes: Uint8Array): Promise<SignatureWithBytes> {
		return this.#exclusive(async () => {
			const state = await this.#requireActive();
			return this.#signChecked(bytes, state, this.#keys.address(state.index + 1));
		});
	}

	/**
	 * Adds the rotation, builds, signs with the current one-time key and executes.
	 *
	 * The transaction is simulated first and not signed if it would fail. If it fails on chain
	 * anyway, the key was revealed without being rotated, so a rotation-only transaction is sent
	 * before the failed result is returned; `KeyExposedError` is thrown if that rotation does not
	 * land either.
	 */
	override signAndExecuteTransaction({
		transaction,
		client,
		skipSimulation = false,
	}: SignAndExecuteOptions): Promise<ExecuteResult> {
		if (client && client !== this.#client) {
			return Promise.reject(
				new OneTimeAuthError('OneTimeAuth only executes through the client it was created with'),
			);
		}

		return this.#exclusive(async () => {
			const state = await this.#requireActive();
			const next = this.#keys.address(state.index + 1);
			await this.#attach(transaction, state, next);

			const bytes = await transaction.build({ client: this.#client, restrictedMoveCalls: [] });
			// build() simulates only when it has something to resolve, and not with every client, so
			// the check that nothing failing gets signed is made here.
			if (!skipSimulation) {
				const simulation = await this.#client.core.simulateTransaction({
					transaction: bytes,
					include: { effects: true },
				});
				if (simulation.$kind === 'FailedTransaction') {
					throw new SimulationFailedError(simulation);
				}
			}

			const { signature } = await this.#signChecked(bytes, state, next);
			// The signature carries the public key of key `state.index`: it is public from here on.
			let result: ExecuteResult;
			try {
				result = await this.#submit(bytes, signature);
			} catch (error) {
				await this.#rescue(state, error);
				throw error;
			}

			if (result.$kind === 'FailedTransaction') {
				await this.#rescue(state, result.FailedTransaction.status.error);
				return result;
			}
			this.#confirm(state.index + 1, state.aliasObjectId);
			return result;
		});
	}

	/** Not supported: every signature must come with a rotation. Use `signTransaction`. */
	override async sign(): Promise<never> {
		throw new OneTimeAuthError('OneTimeAuth only signs transactions that rotate its key');
	}

	/** Not supported: every signature must come with a rotation. Use `signTransaction`. */
	override async signWithIntent(): Promise<never> {
		throw new OneTimeAuthError('OneTimeAuth only signs transactions that rotate its key');
	}

	/** Not supported: a signed message would reveal the current key without rotating it. */
	override async signPersonalMessage(): Promise<never> {
		throw new OneTimeAuthError(
			'OneTimeAuth does not sign personal messages: that would reveal the current key without rotating it',
		);
	}

	/** Runs operations one at a time: each one consumes the current key. */
	#exclusive<T>(operation: () => Promise<T>): Promise<T> {
		const run = this.#lock.then(operation, operation);
		this.#lock = run.catch(() => {});
		return run;
	}

	async #sync(): Promise<OneTimeAuthState> {
		for (let attempt = 0; ; attempt++) {
			const state = await this.#read();
			// A read that is behind a transaction this instance saw succeed comes from a lagging node.
			const stale =
				this.#floor !== undefined && (state.status !== 'active' || state.index < this.#floor);
			if (!stale) {
				this.#state = state;
				if (state.status === 'active') this.#setHint(state.index);
				return state;
			}
			if (attempt >= STALE_READ_RETRIES) {
				throw new OneTimeAuthError(
					`The alias set read from the node is behind index ${this.#floor}, which this instance already reached. The node is lagging, or the alias set was changed elsewhere.`,
				);
			}
			await sleep(STALE_READ_DELAY_MS);
		}
	}

	async #read(): Promise<OneTimeAuthState> {
		const { addressAliases } = await this.#client.core.getAddressAliases({
			address: this.account,
		});
		const aliasObjectId = addressAliases.objectId;
		const aliases = addressAliases.aliases.map((alias) => normalizeSuiAddress(alias));

		if (aliases.length === 1 && aliases[0] === this.account) {
			return { status: 'not-enrolled', aliasObjectId, enabled: addressAliases.enabled };
		}
		if (aliases.length !== 1) {
			throw new UnknownAliasError(
				`Account has ${aliases.length} aliases; OneTimeAuth manages exactly one`,
			);
		}
		const [alias] = aliases;
		return { status: 'active', aliasObjectId, index: await this.#findIndex(alias), alias };
	}

	/** Finds `i` with `address(i) === alias`: near the hint first, then onward, then backward. */
	async #findIndex(alias: string): Promise<number> {
		const hint = this.#hint;
		const matches = (index: number) => index >= 0 && this.#keys.address(index) === alias;

		for (const index of [hint, hint + 1, hint - 1]) {
			if (matches(index)) return index;
		}
		let probed = 0;
		for (let index = hint + 2; index <= hint + this.#scanLimit; index++) {
			if (matches(index)) return index;
			if (++probed % 256 === 0) await sleep(0);
		}
		for (let index = hint - 2; index >= 0; index--) {
			if (matches(index)) return index;
			if (++probed % 256 === 0) await sleep(0);
		}
		throw new UnknownAliasError(
			`Alias ${alias} is not a one-time key of this mnemonic on this chain (searched indices 0 to ${hint + this.#scanLimit})`,
		);
	}

	async #requireActive(): Promise<ActiveState> {
		const state = await this.#sync();
		if (state.status !== 'active') {
			throw new NotEnrolledError(`Account ${this.account} is not enrolled; call enroll() first`);
		}
		return state;
	}

	#setHint(index: number) {
		if (index === this.#hint) return;
		this.#hint = index;
		this.#onIndexChange?.(index);
	}

	/** Records that the chain has reached `index`, as seen from a transaction that succeeded. */
	#confirm(index: number, aliasObjectId: string) {
		this.#floor = index;
		this.#state = { status: 'active', aliasObjectId, index, alias: this.#keys.address(index) };
		this.#setHint(index);
	}

	async #aliasObject(aliasObjectId: string): Promise<{ version: string; startVersion: string }> {
		const { object } = await this.#client.core.getObject({ objectId: aliasObjectId });
		const owner = object.owner.ConsensusAddressOwner;
		if (!owner) {
			throw new OneTimeAuthError(`Unexpected owner of alias set ${aliasObjectId}`);
		}
		this.#startVersion = owner.startVersion;
		return { version: object.version, startVersion: owner.startVersion };
	}

	async #aliasStartVersion(aliasObjectId: string): Promise<string> {
		return this.#startVersion ?? (await this.#aliasObject(aliasObjectId)).startVersion;
	}

	/** True if the alias set was an input to any transaction after the one that created it. */
	async #hasHistory(aliasObjectId: string): Promise<boolean> {
		const { version, startVersion } = await this.#aliasObject(aliasObjectId);
		return version !== startVersion;
	}

	async #attach(transaction: Transaction, state: ActiveState, next: string) {
		const data = transaction.getData();
		if (!data.sender) {
			transaction.setSender(this.account);
		} else if (normalizeSuiAddress(data.sender) !== this.account) {
			throw new RotationCheckError(
				`Transaction sender is ${data.sender}, expected the account ${this.account}`,
			);
		}

		const expected = { sender: this.account, aliasObjectId: state.aliasObjectId, next };
		if (!checkRotation(data, expected, { built: false })) {
			addRotation(
				transaction,
				state.aliasObjectId,
				next,
				await this.#aliasStartVersion(state.aliasObjectId),
			);
		}
	}

	#signChecked(bytes: Uint8Array, state: ActiveState, next: string): Promise<SignatureWithBytes> {
		assertRotation(Transaction.from(bytes).getData(), {
			sender: this.account,
			aliasObjectId: state.aliasObjectId,
			next,
		});
		return this.#keys.keypair(state.index).signTransaction(bytes);
	}

	/** A transaction signed by key `state.index` that only replaces the alias with `next`. */
	async #rotateTo(
		state: ActiveState,
		next: string,
	): Promise<Extract<ExecuteResult, { $kind: 'Transaction' }>> {
		const transaction = new Transaction();
		await this.#attach(transaction, state, next);
		const bytes = await transaction.build({ client: this.#client, restrictedMoveCalls: [] });
		const { signature } = await this.#signChecked(bytes, state, next);
		const result = await this.#submit(bytes, signature);
		if (result.$kind === 'FailedTransaction') {
			throw new OneTimeAuthError(
				`Rotation failed: ${describe(result.FailedTransaction.status.error)}`,
			);
		}
		return result;
	}

	/**
	 * Key `state.index` signed a transaction that did not rotate it. If it is still the alias,
	 * rotate it out now.
	 */
	async #rescue(state: ActiveState, reason: unknown) {
		try {
			const current = await this.#sync();
			if (current.status !== 'active' || current.index !== state.index) return;
			await this.#rotateTo(current, this.#keys.address(current.index + 1));
			this.#confirm(current.index + 1, current.aliasObjectId);
		} catch (cause) {
			throw new KeyExposedError(state.index, describe(reason), { cause });
		}
	}

	async #executeWithBaseKey(transaction: Transaction, base: Secp256k1Keypair) {
		transaction.setSender(this.account);
		const bytes = await transaction.build({ client: this.#client, restrictedMoveCalls: [] });
		const { signature } = await base.signTransaction(bytes);
		const result = await this.#submit(bytes, signature);
		if (result.$kind === 'FailedTransaction') {
			throw new OneTimeAuthError(
				`Enrollment transaction failed: ${describe(result.FailedTransaction.status.error)}`,
			);
		}
	}

	/** Executes and waits until the node this client reads from has the transaction. */
	async #submit(bytes: Uint8Array, signature: string): Promise<ExecuteResult> {
		const include = { transaction: true, effects: true } as const;
		for (let attempt = 0; ; attempt++) {
			try {
				const result = await this.#client.core.executeTransaction({
					transaction: bytes,
					signatures: [signature],
					include,
				});
				await this.#client.core.waitForTransaction({ result });
				return result;
			} catch (error) {
				if (isAliasLag(error) && attempt < ALIAS_LAG_RETRIES) {
					await sleep(ALIAS_LAG_DELAY_MS * 2 ** attempt);
					continue;
				}
				// The error does not say whether the transaction landed, so look for it.
				try {
					return await this.#client.core.waitForTransaction({
						digest: TransactionDataBuilder.getDigestFromBytes(bytes),
						include,
						timeout: LANDED_CHECK_TIMEOUT_MS,
					});
				} catch {
					throw error;
				}
			}
		}
	}
}

/**
 * Whether a submission was rejected because the validator's view of the alias set does not match
 * the signer, which happens briefly after a rotation. The patterns are the messages of Sui's
 * `SignerSignatureAbsent` and `AliasesChanged` errors.
 */
function isAliasLag(error: unknown): boolean {
	return /Required Signature from .* is absent|set of aliases for a required signer changed/i.test(
		describe(error),
	);
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}
