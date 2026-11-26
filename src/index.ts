export { OneTimeAuth } from './one-time-auth.js';
export type {
	ActiveState,
	OneTimeAuthOptions,
	OneTimeAuthState,
	SignAndExecuteOptions,
} from './one-time-auth.js';
export {
	derivePrfKey,
	deriveSalt,
	OneTimeKeys,
	tweakPublicKey,
	tweakSecretKey,
} from './derive.js';
export type { OneTimeKeysOptions } from './derive.js';
export { addRotation, assertRotation, checkRotation } from './alias.js';
export type { ExpectedRotation } from './alias.js';
export {
	KeyExposedError,
	NotEnrolledError,
	OneTimeAuthError,
	RotationCheckError,
	SimulationFailedError,
	UnknownAliasError,
} from './errors.js';
