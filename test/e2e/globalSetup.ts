import { spawn } from 'node:child_process';
import { once } from 'node:events';

import { isLocalnetUp, network } from './network.js';

const STARTUP_TIMEOUT_MS = 150_000;

/**
 * Starts a local network with `sui start` unless one is already running, and stops it afterwards.
 * Does nothing for devnet and testnet.
 */
export default async function setup() {
	if (network !== 'localnet' || (await isLocalnetUp())) return;

	const child = spawn('sui', ['start', '--with-faucet', '--force-regenesis'], {
		stdio: 'ignore',
	});
	const failed = once(child, 'error').then(([error]) => {
		throw new Error(`Could not run "sui start": ${error}`);
	});
	const exited = once(child, 'exit').then(([code]) => {
		throw new Error(`"sui start" exited with code ${code} before the network was up`);
	});

	const ready = (async () => {
		const deadline = Date.now() + STARTUP_TIMEOUT_MS;
		while (!(await isLocalnetUp())) {
			if (Date.now() > deadline) throw new Error('Timed out waiting for the local network');
			await new Promise((resolve) => setTimeout(resolve, 1_000));
		}
	})();

	try {
		await Promise.race([ready, failed, exited]);
	} catch (error) {
		child.kill('SIGKILL');
		throw error;
	}
	// The network is up: its later exit is the teardown, not a failure.
	exited.catch(() => {});
	failed.catch(() => {});

	return async () => {
		child.kill('SIGINT');
		await once(child, 'exit').catch(() => {});
	};
}
