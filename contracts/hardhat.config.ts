import { HardhatUserConfig } from "hardhat/config"
import "@nomicfoundation/hardhat-toolbox"
import * as fs from "fs"
import * as path from "path"

const envPath = path.join(__dirname, ".env")
if (fs.existsSync(envPath)) {
	for (const line of fs.readFileSync(envPath, "utf8").split("\n")) {
		const trimmed = line.trim()
		if (!trimmed || trimmed.startsWith("#")) continue
		const [k, ...v] = trimmed.replace(/^export\s+/, "").split("=")
		if (k && !process.env[k.trim()]) {
			process.env[k.trim()] = v.join("=").trim().replace(/^["']|["']$/g, "")
		}
	}
}

const config: HardhatUserConfig = {
	solidity: {
		version: "0.8.28",
		settings: {
			optimizer: { enabled: true, runs: 200 },
			viaIR: true, // setRecord's wide calldata needs the IR pipeline
		},
	},
	networks: {
		localhost: {
			url: process.env.RPC_URL || "http://127.0.0.1:8545",
		},
		// Sepolia is configured but intentionally not used by default; the demo
		// target is the local Hardhat network. Provide SEPOLIA_RPC_URL and
		// SEPOLIA_PRIVATE_KEY to deploy.
		sepolia: {
			url: process.env.SEPOLIA_RPC_URL || "https://rpc.sepolia.org",
			accounts: process.env.SEPOLIA_PRIVATE_KEY ? [process.env.SEPOLIA_PRIVATE_KEY] : [],
		},
	},
}

export default config
