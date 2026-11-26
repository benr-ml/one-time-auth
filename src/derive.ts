import { decodeSuiPrivateKey, mnemonicToSeed } from '@mysten/sui/cryptography';
import {
	DEFAULT_SECP256K1_DERIVATION_PATH,
	Secp256k1Keypair,
	Secp256k1PublicKey,
} from '@mysten/sui/keypairs/secp256k1';
import { fromBase58, fromHex, normalizeSuiAddress } from '@mysten/sui/utils';
import { mapHashToField } from '@noble/curves/abstract/modular.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { bytesToNumberBE, concatBytes, numberToBytesBE } from '@noble/curves/utils.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';

const Point = secp256k1.Point;
/** Order of the secp256k1 group. */
const N = Point.Fn.ORDER;

const encoder = new TextEncoder();
const KEY_DOMAIN = encoder.encode('OneTimeAuth/v1/key');
const SALT_DOMAIN = encoder.encode('OneTimeAuth/v1/salt');

/**
 * The PRF key that all salts are derived from.
 *
 * It is computed from the BIP39 seed, not from the base secret key. The base public key becomes
 * public at enrollment, so anything computable from the base secret key must be assumed known to
 * an attacker who can break secp256k1.
 */
export function derivePrfKey(seed: Uint8Array): Uint8Array {
	return hmac(sha512, KEY_DOMAIN, seed);
}

/**
 * `s_i = HMAC-SHA512(prfKey, domain ‖ chain ‖ account ‖ LE64(i))`, reduced to `[1, n-1]`.
 *
 * Binding the chain and the account means a key revealed on one network (or for one account)
 * says nothing about the same index elsewhere.
 */
export function deriveSalt(
	prfKey: Uint8Array,
	chainIdentifier: string,
	account: string,
	index: number,
): bigint {
	const message = concatBytes(
		SALT_DOMAIN,
		chainIdentifierBytes(chainIdentifier),
		fromHex(normalizeSuiAddress(account)),
		indexBytes(index),
	);
	// 64 bytes mapped to a 32-byte field: the bias is below 2^-128.
	return bytesToNumberBE(mapHashToField(hmac(sha512, prfKey, message), N));
}

/** `sk + salt mod n`, as a 32-byte secret key. */
export function tweakSecretKey(secretKey: Uint8Array, salt: bigint): Uint8Array {
	const tweaked = Point.Fn.add(bytesToNumberBE(secretKey), salt);
	if (tweaked === 0n) {
		throw new Error('Derived secret key is zero');
	}
	return numberToBytesBE(tweaked, 32);
}

/** `pk + salt·G`, as a compressed public key. Needs no secret key. */
export function tweakPublicKey(publicKey: Uint8Array, salt: bigint): Uint8Array {
	const tweaked = Point.fromBytes(publicKey).add(Point.BASE.multiply(salt));
	if (tweaked.is0()) {
		throw new Error('Derived public key is the point at infinity');
	}
	return tweaked.toBytes(true);
}

function chainIdentifierBytes(chainIdentifier: string): Uint8Array {
	const bytes = fromBase58(chainIdentifier);
	if (bytes.length !== 32) {
		throw new Error(
			`Expected the chain identifier to be a base58 32-byte digest, got "${chainIdentifier}"`,
		);
	}
	return bytes;
}

function indexBytes(index: number): Uint8Array {
	assertIndex(index);
	const bytes = new Uint8Array(8);
	new DataView(bytes.buffer).setBigUint64(0, BigInt(index), true);
	return bytes;
}

export function assertIndex(index: number) {
	if (!Number.isSafeInteger(index) || index < 0) {
		throw new Error(`Invalid one-time key index: ${index}`);
	}
}

export interface OneTimeKeysOptions {
	mnemonic: string;
	/** BIP32 path of the base key. Defaults to Sui's secp256k1 path, `m/54'/784'/0'/0/0`. */
	path?: string;
	/** Base58 genesis checkpoint digest, as returned by `client.core.getChainIdentifier()`. */
	chainIdentifier: string;
}

/**
 * The key schedule of one account on one chain: a base key from the mnemonic, and for every index
 * `i` a one-time key `sk_i = sk_base + s_i`, `pk_i = pk_base + s_i·G`.
 */
export class OneTimeKeys {
	/** The account address: the Sui address of the base public key. It never changes. */
	readonly account: string;
	readonly chainIdentifier: string;

	#base: Secp256k1Keypair;
	#baseSecretKey: Uint8Array;
	#basePublicKey: Uint8Array;
	#prfKey: Uint8Array;

	constructor({
		mnemonic,
		path = DEFAULT_SECP256K1_DERIVATION_PATH,
		chainIdentifier,
	}: OneTimeKeysOptions) {
		this.#base = Secp256k1Keypair.deriveKeypair(mnemonic, path);
		this.#baseSecretKey = decodeSuiPrivateKey(this.#base.getSecretKey()).secretKey;
		this.#basePublicKey = this.#base.getPublicKey().toRawBytes();
		this.#prfKey = derivePrfKey(mnemonicToSeed(mnemonic));
		this.account = this.#base.toSuiAddress();
		// Fail early on a malformed identifier rather than at the first derivation.
		chainIdentifierBytes(chainIdentifier);
		this.chainIdentifier = chainIdentifier;
	}

	/** The key behind the account address. Only used to enroll. */
	baseKeypair(): Secp256k1Keypair {
		return this.#base;
	}

	salt(index: number): bigint {
		return deriveSalt(this.#prfKey, this.chainIdentifier, this.account, index);
	}

	/** The signer for one-time key `index`. */
	keypair(index: number): Secp256k1Keypair {
		return Secp256k1Keypair.fromSecretKey(tweakSecretKey(this.#baseSecretKey, this.salt(index)));
	}

	/** One-time public key `index`, computed from the base public key and the salt only. */
	publicKey(index: number): Secp256k1PublicKey {
		return new Secp256k1PublicKey(tweakPublicKey(this.#basePublicKey, this.salt(index)));
	}

	/** The Sui address of one-time key `index`: what the account's alias is set to. */
	address(index: number): string {
		return this.publicKey(index).toSuiAddress();
	}
}
