import { getFaucetHost } from '@mysten/sui/faucet';
import { SuiGrpcClient } from '@mysten/sui/grpc';

type Network = 'localnet' | 'devnet' | 'testnet';

/** `OTA_E2E_NETWORK` picks the network; the default is a local one started by the test run. */
export const network = (process.env.OTA_E2E_NETWORK ?? 'localnet') as Network;

const baseUrl =
	network === 'localnet' ? 'http://127.0.0.1:9000' : `https://fullnode.${network}.sui.io:443`;

export const faucetHost = getFaucetHost(network);

export function createClient(options: { restrictedMoveCalls?: readonly string[] } = {}) {
	return new SuiGrpcClient({ network, baseUrl, ...options });
}

export async function isLocalnetUp(): Promise<boolean> {
	try {
		await createClient().core.getChainIdentifier();
		// Any HTTP answer means the faucet is listening.
		await fetch(faucetHost);
		return true;
	} catch {
		return false;
	}
}
