import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers"
import { ethers } from "hardhat"

/**
 * Commit-reveal registration (UC-1 front-running defense): commit, wait out
 * MIN_COMMITMENT_AGE, then reveal via register(). Mirrors what `ddns
 * register` and contracts/scripts/seed.ts do against a real chain — tests
 * that only care about the end state (a registered domain) use this instead
 * of re-deriving the two-step flow inline.
 */
export async function commitAndRegister(
	dapp: any,
	signer: any,
	name: string,
	pubKey: string,
	value: bigint,
	opts: { secret?: string; skipWait?: boolean } = {},
) {
	const secret = opts.secret ?? ethers.hexlify(ethers.randomBytes(32))
	const commitment = await dapp.makeCommitment(name, signer.address, pubKey, secret)
	await dapp.connect(signer).commit(commitment)
	if (!opts.skipWait) {
		await time.increase(await dapp.MIN_COMMITMENT_AGE())
	}
	return dapp.connect(signer).register(name, pubKey, secret, { value })
}
