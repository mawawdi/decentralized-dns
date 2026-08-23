import { time } from "@nomicfoundation/hardhat-toolbox/network-helpers"
import { ethers, network } from "hardhat"
import { execFileSync } from "child_process"
import * as fs from "fs"
import * as path from "path"
import { signRecord } from "./recordSig"

/**
 * Seeds a freshly deployed local chain with demo data used by resolver
 * integration tests and the demo script: registers "example" and writes an
 * A record plus two SVC records with different selectors.
 *
 * Reads contract addresses from deployments/<network>.json (run deploy.ts
 * first). Signs records with the second hardhat account (alice).
 */
const ALICE_PK = "0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d" // hardhat account #1

/** MiMC commitment matching the gnark circuit, via the Go helper (cmd/record-commit). */
function commitmentOf(
	name: string,
	type: string,
	selector: string,
	ttl: number,
	generation: bigint,
	fieldNames: string[],
	fieldValues: string[],
): string {
	const out = execFileSync("go", ["run", "./cmd/record-commit"], {
		cwd: path.join(__dirname, "..", "..", "resolver"),
		input: JSON.stringify({ name, type, selector, ttl, generation: Number(generation), fieldNames, fieldValues }),
	})
	return out.toString().trim()
}

async function main() {
	const file = path.join(__dirname, "..", "deployments", `${network.name}.json`)
	const { contracts } = JSON.parse(fs.readFileSync(file, "utf8"))
	const [, alice] = await ethers.getSigners()
	const aliceWallet = new ethers.Wallet(ALICE_PK)

	const dapp = await ethers.getContractAt("NamespaceDApp", contracts.NamespaceDApp)

	const price = await dapp.priceOf("example")
	// alice's uncompressed secp256k1 public key as the on-chain pubKey
	const pubKey = ethers.SigningKey.computePublicKey(ALICE_PK, false)

	// Commit-reveal registration (UC-1 front-running defense): commit to a
	// hash of the name first, then reveal via register() once
	// MIN_COMMITMENT_AGE has elapsed. time.increase() fast-forwards the local
	// chain's clock instead of sleeping in real time.
	const secret = ethers.hexlify(ethers.randomBytes(32))
	const commitment = await dapp.makeCommitment("example", alice.address, pubKey, secret)
	await (await dapp.connect(alice).commit(commitment)).wait()
	await time.increase(await dapp.MIN_COMMITMENT_AGE())
	await (await dapp.connect(alice).register("example", pubKey, secret, { value: price })).wait()
	console.log("registered 'example' for", alice.address)

	// Records are signed under (and resolve only at) the domain's current
	// generation, so bind every signature/commitment to it.
	const [, , , generation] = await dapp.getDomain("example")

	const set = async (
		recordType: string,
		selector: string,
		fieldNames: string[],
		fieldValues: string[],
		ttl: number,
	) => {
		const sig = await signRecord(aliceWallet, "example", recordType, selector, ttl, generation, fieldNames, fieldValues)
		const commitment = commitmentOf("example", recordType, selector, ttl, generation, fieldNames, fieldValues)
		await (
			await dapp
				.connect(alice)
				.setRecord("example", recordType, selector, fieldNames, fieldValues, ttl, sig, commitment)
		).wait()
	}

	await set("A", "", ["address"], ["93.184.216.34"], 3600)
	await set(
		"SVC",
		"port=25&service=SMTP&transport=TCP",
		["target", "service", "transport", "port"],
		["mail.example", "SMTP", "TCP", "25"],
		300,
	)
	await set(
		"SVC",
		"port=443&service=HTTP&transport=QUIC",
		["target", "service", "transport", "port"],
		["web.example", "HTTP", "QUIC", "443"],
		300,
	)
	console.log("seeded A + 2 SVC records for 'example' (owner-signed, ZK-committed)")
}

main().catch((err) => {
	console.error(err)
	process.exitCode = 1
})
