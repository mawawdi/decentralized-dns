import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers"
import { expect } from "chai"
import { ethers } from "hardhat"

const BASE_PRICE = ethers.parseEther("0.01")
const YEAR = 365n * 24n * 60n * 60n
const PUBKEY = "0x" + "11".repeat(65) // dummy 65-byte secp256k1 pubkey
const PUBKEY2 = "0x" + "22".repeat(65)

describe("NamespaceDApp", () => {
	async function deployFixture() {
		const [treasurer, alice, bob] = await ethers.getSigners()
		const registry = await (await ethers.getContractFactory("RecordSchemaRegistry")).deploy()
		const factory = await ethers.getContractFactory("NamespaceDApp")
		const dapp = await factory.deploy(BASE_PRICE, await registry.getAddress())
		return { dapp, registry, treasurer, alice, bob }
	}

	describe("pricing", () => {
		it("scales inversely with name length", async () => {
			const { dapp } = await loadFixture(deployFixture)
			expect(await dapp.priceOf("a")).to.equal(BASE_PRICE * 16n)
			expect(await dapp.priceOf("ab")).to.equal(BASE_PRICE * 8n)
			expect(await dapp.priceOf("abc")).to.equal(BASE_PRICE * 4n)
			expect(await dapp.priceOf("abcd")).to.equal(BASE_PRICE * 2n)
			expect(await dapp.priceOf("abcde")).to.equal(BASE_PRICE)
			expect(await dapp.priceOf("a".repeat(63))).to.equal(BASE_PRICE)
		})

		it("rejects invalid lengths", async () => {
			const { dapp } = await loadFixture(deployFixture)
			await expect(dapp.priceOf("")).to.be.revertedWithCustomError(dapp, "InvalidName")
			await expect(dapp.priceOf("a".repeat(64))).to.be.revertedWithCustomError(dapp, "InvalidName")
		})
	})

	describe("register (UC-1)", () => {
		it("registers a free name and emits Registered", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			const tx = dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })
			await expect(tx).to.emit(dapp, "Registered")

			const [owner, pubKey, expiry, generation] = await dapp.getDomain("example")
			expect(owner).to.equal(alice.address)
			expect(pubKey).to.equal(PUBKEY)
			expect(generation).to.equal(1n)
			const now = BigInt(await time.latest())
			expect(expiry).to.equal(now + YEAR)
			expect(await dapp.ownerOf("example")).to.equal(alice.address)
			expect(await dapp.available("example")).to.equal(false)
		})

		it("rejects an insufficient fee", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await expect(dapp.connect(alice).register("ab", PUBKEY, { value: BASE_PRICE })).to.be.revertedWithCustomError(
				dapp,
				"InsufficientFee",
			)
		})

		it("refunds overpayment", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			const before = await ethers.provider.getBalance(alice.address)
			const tx = await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE * 3n })
			const rcpt = await tx.wait()
			const gas = rcpt!.gasUsed * rcpt!.gasPrice
			const after = await ethers.provider.getBalance(alice.address)
			expect(before - after).to.equal(BASE_PRICE + gas) // only the price kept
			expect(await ethers.provider.getBalance(dapp.target)).to.equal(BASE_PRICE)
		})

		it("rejects a taken name", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })
			await expect(dapp.connect(bob).register("example", PUBKEY2, { value: BASE_PRICE })).to.be.revertedWithCustomError(
				dapp,
				"NameUnavailable",
			)
		})

		it("allows re-registration after expiry and bumps generation", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })
			await time.increase(YEAR + 1n)
			expect(await dapp.available("example")).to.equal(true)
			expect(await dapp.ownerOf("example")).to.equal(ethers.ZeroAddress)

			await dapp.connect(bob).register("example", PUBKEY2, { value: BASE_PRICE })
			const [owner, pubKey, , generation] = await dapp.getDomain("example")
			expect(owner).to.equal(bob.address)
			expect(pubKey).to.equal(PUBKEY2)
			expect(generation).to.equal(2n)
		})

		it("rejects malformed names", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			for (const bad of ["UPPER", "-lead", "trail-", "un_der", "dot.ted", "spa ce"]) {
				await expect(
					dapp.connect(alice).register(bad, PUBKEY, { value: BASE_PRICE * 16n }),
				).to.be.revertedWithCustomError(dapp, "InvalidName")
			}
		})

		it("rejects an empty or oversized pubKey", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await expect(dapp.connect(alice).register("example", "0x", { value: BASE_PRICE })).to.be.revertedWithCustomError(
				dapp,
				"InvalidPubKey",
			)
			await expect(
				dapp.connect(alice).register("example", "0x" + "aa".repeat(129), { value: BASE_PRICE }),
			).to.be.revertedWithCustomError(dapp, "InvalidPubKey")
		})
	})

	describe("renew", () => {
		it("extends expiry by one period", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })
			const [, , expiry0] = await dapp.getDomain("example")

			// anyone may pay for renewal
			await expect(dapp.connect(bob).renew("example", { value: BASE_PRICE })).to.emit(dapp, "Renewed")
			const [, , expiry1] = await dapp.getDomain("example")
			expect(expiry1).to.equal(expiry0 + YEAR)
		})

		it("rejects renewal of unregistered or expired domains", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await expect(dapp.connect(alice).renew("ghost", { value: BASE_PRICE })).to.be.revertedWithCustomError(
				dapp,
				"DomainNotRegistered",
			)

			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })
			await time.increase(YEAR + 1n)
			await expect(dapp.connect(alice).renew("example", { value: BASE_PRICE })).to.be.revertedWithCustomError(
				dapp,
				"DomainExpired",
			)
		})

		it("rejects an insufficient renewal fee", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })
			await expect(dapp.connect(alice).renew("example", { value: BASE_PRICE - 1n })).to.be.revertedWithCustomError(
				dapp,
				"InsufficientFee",
			)
		})
	})

	describe("transfer (UC-3)", () => {
		it("atomically rewrites owner and pubKey", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })
			await expect(dapp.connect(alice).transfer("example", bob.address, PUBKEY2))
				.to.emit(dapp, "Transferred")
				.withArgs(ethers.keccak256(ethers.toUtf8Bytes("example")), alice.address, bob.address, PUBKEY2)
			const [owner, pubKey] = await dapp.getDomain("example")
			expect(owner).to.equal(bob.address)
			expect(pubKey).to.equal(PUBKEY2)
		})

		it("rejects transfer by non-owner, to zero, or when expired", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })

			await expect(dapp.connect(bob).transfer("example", bob.address, PUBKEY2)).to.be.revertedWithCustomError(
				dapp,
				"NotDomainOwner",
			)
			await expect(dapp.connect(alice).transfer("example", ethers.ZeroAddress, PUBKEY2)).to.be.revertedWithCustomError(
				dapp,
				"ZeroAddress",
			)

			await time.increase(YEAR + 1n)
			await expect(dapp.connect(alice).transfer("example", bob.address, PUBKEY2)).to.be.revertedWithCustomError(
				dapp,
				"DomainExpired",
			)
		})
	})

	describe("withdraw", () => {
		it("lets only the treasurer collect fees", async () => {
			const { dapp, treasurer, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })

			await expect(dapp.connect(alice).withdraw(alice.address)).to.be.revertedWithCustomError(dapp, "NotTreasurer")

			const before = await ethers.provider.getBalance(bob.address)
			await expect(dapp.connect(treasurer).withdraw(bob.address))
				.to.emit(dapp, "Withdrawn")
				.withArgs(bob.address, BASE_PRICE)
			const after = await ethers.provider.getBalance(bob.address)
			expect(after - before).to.equal(BASE_PRICE)
			expect(await ethers.provider.getBalance(dapp.target)).to.equal(0n)
		})
	})

	describe("record key housekeeping (generation-scoped, anti-griefing)", () => {
		it("a departing owner's records never appear for, or slow down, the next owner", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).register("example", PUBKEY, { value: BASE_PRICE })

			// Alice writes several distinct records under different selectors —
			// the pattern a departing owner could otherwise use to permanently
			// bloat listRecords() for whoever registers the name next.
			for (let i = 0; i < 5; i++) {
				await dapp
					.connect(alice)
					.setRecord("example", "A", `sel${i}`, ["address"], ["1.2.3.4"], 3600, "0x", ethers.ZeroHash)
			}
			expect(await dapp.listRecords("example")).to.have.length(5)

			await dapp.connect(alice).transfer("example", bob.address, PUBKEY2)
			// Bob's new generation starts with an empty key list — none of
			// alice's five records carry over.
			expect(await dapp.listRecords("example")).to.have.length(0)

			await dapp.connect(bob).setRecord("example", "A", "", ["address"], ["5.6.7.8"], 3600, "0x", ethers.ZeroHash)
			// Exactly bob's one record, not six: proves the previous
			// generation's keys were never iterated, not merely filtered out.
			expect(await dapp.listRecords("example")).to.have.length(1)
		})
	})
})
