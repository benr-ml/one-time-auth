import type { SuiClientTypes } from '@mysten/sui/client';

export class OneTimeAuthError extends Error {
	constructor(message: string, options?: ErrorOptions) {
		super(message, options);
		this.name = new.target.name;
	}
}

/** The account's alias set is not one this instance manages. */
export class NotEnrolledError extends OneTimeAuthError {}

/** The on-chain alias set does not match any key derived from this mnemonic. */
export class UnknownAliasError extends OneTimeAuthError {}

/** A transaction does not carry exactly the rotation the signer requires. */
export class RotationCheckError extends OneTimeAuthError {}

/** The transaction would fail, so it was not signed and no key was revealed. */
export class SimulationFailedError extends OneTimeAuthError {
	constructor(readonly result: SuiClientTypes.SimulateTransactionResult<{ effects: true }>) {
		const error = result.FailedTransaction?.status.error;
		super(`Simulation failed, transaction not signed: ${describe(error)}`);
	}
}

/**
 * The current one-time key has signed a transaction that did not rotate it, and the follow-up
 * rotation did not land either. The key stays valid until a rotation succeeds, so call
 * `rotate()` as soon as the cause is fixed.
 */
export class KeyExposedError extends OneTimeAuthError {
	constructor(
		readonly index: number,
		/** Why the signed transaction did not rotate the key. */
		readonly reason: string,
		options?: ErrorOptions,
	) {
		super(
			`One-time key ${index} signed a transaction that did not rotate it (${reason}), and the rescue rotation failed: ${describe(options?.cause)}`,
			options,
		);
	}
}

export function describe(error: unknown): string {
	if (error instanceof Error) return error.message;
	if (typeof error === 'object' && error !== null && 'message' in error) {
		return String((error as { message: unknown }).message);
	}
	return typeof error === 'string' ? error : JSON.stringify(error);
}
