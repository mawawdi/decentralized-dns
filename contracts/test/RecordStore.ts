import { loadFixture, time } from "@nomicfoundation/hardhat-toolbox/network-helpers"
import { expect } from "chai"
import { ethers } from "hardhat"
import { commitAndRegister } from "./helpers"

const BASE_PRICE = ethers.parseEther("0.01")
const YEAR = 365n * 24n * 60n * 60n
const PUBKEY = "0x" + "11".repeat(65)
const PUBKEY2 = "0x" + "22".repeat(65)
const SIG = "0x" + "ab".repeat(65) // placeholder owner signature
const NO_COMMIT = ethers.ZeroHash

describe("RecordSchemaRegistry + record store", () => {
	async function deployFixture() {
		const [treasurer, alice, bob] = await ethers.getSigners()
		const registry = await (await ethers.getContractFactory("RecordSchemaRegistry")).deploy()
		const dapp = await (
			await ethers.getContractFactory("NamespaceDApp")
		).deploy(BASE_PRICE, await registry.getAddress())
		await commitAndRegister(dapp, alice, "example", PUBKEY, BASE_PRICE)
		return { dapp, registry, treasurer, alice, bob }
	}

	describe("schema registry (UC-9)", () => {
		it("seeds the built-in types", async () => {
			const { registry } = await loadFixture(deployFixture)
			expect(await registry.listTypes()).to.deep.equal(["A", "AAAA", "MX", "SVC", "ResourceRef"])
			const svc = await registry.getSchema("SVC")
			expect(svc.map((f) => [f.name, f.mandatory])).to.deep.equal([
				["target", true],
				["service", true],
				["transport", true],
				["port", false],
			])
		})

		it("declares a new GEO type permissionlessly", async () => {
			const { registry, bob } = await loadFixture(deployFixture)
			await expect(registry.connect(bob).declareType("GEO", ["lat", "lon"], ["alt"]))
				.to.emit(registry, "TypeDeclared")
				.withArgs(ethers.keccak256(ethers.toUtf8Bytes("GEO")), "GEO", bob.address, 2, 1)
			expect(await registry.typeExists("GEO")).to.equal(true)
			const mandatory = await registry.mandatoryFields(ethers.keccak256(ethers.toUtf8Bytes("GEO")))
			expect(mandatory).to.deep.equal(["lat", "lon"])
		})

		it("rejects duplicate types, bad names, and duplicate fields", async () => {
			const { registry } = await loadFixture(deployFixture)
			await expect(registry.declareType("A", ["x"], [])).to.be.revertedWithCustomError(registry, "TypeAlreadyExists")
			await expect(registry.declareType("bad type", ["x"], [])).to.be.revertedWithCustomError(
				registry,
				"InvalidTypeName",
			)
			await expect(registry.declareType("DUP", ["x", "x"], [])).to.be.revertedWithCustomError(
				registry,
				"DuplicateField",
			)
			await expect(
				registry.declareType(
					"BIG",
					Array.from({ length: 17 }, (_, i) => `f${i}`),
					[],
				),
			).to.be.revertedWithCustomError(registry, "TooManyFields")
			await expect(registry.getSchema("GHOST")).to.be.revertedWithCustomError(registry, "UnknownType")
		})
	})

	describe("setRecord (UC-2)", () => {
		it("stores a valid A record and emits RecordSet", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await expect(
				dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 3600, SIG, NO_COMMIT),
			).to.emit(dapp, "RecordSet")

			const rec = await dapp.lookup("example", "A", "")
			expect(rec.exists).to.equal(true)
			expect(rec.recordType).to.equal("A")
			expect(rec.fieldNames).to.deep.equal(["address"])
			expect(rec.fieldValues).to.deep.equal(["1.2.3.4"])
			expect(rec.ttl).to.equal(3600)
			expect(rec.ownerSig).to.equal(SIG)
		})

		it("upserts an existing record", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 3600, SIG, NO_COMMIT)
			await dapp.connect(alice).setRecord("example", "A", "", ["address"], ["5.6.7.8"], 60, SIG, NO_COMMIT)
			const rec = await dapp.lookup("example", "A", "")
			expect(rec.fieldValues).to.deep.equal(["5.6.7.8"])
			expect(rec.ttl).to.equal(60)
			expect(await dapp.listRecords("example")).to.have.length(1)
		})

		it("enforces schema: unknown type and missing mandatory fields", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await expect(
				dapp.connect(alice).setRecord("example", "GHOST", "", ["x"], ["1"], 60, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "UnknownRecordType")

			await expect(dapp.connect(alice).setRecord("example", "MX", "", ["host"], ["mail.example"], 60, SIG, NO_COMMIT))
				.to.be.revertedWithCustomError(dapp, "MissingMandatoryField")
				.withArgs("priority")
		})

		it("validates shape: array mismatch, ttl, selector length", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await expect(
				dapp.connect(alice).setRecord("example", "A", "", ["address", "extra"], ["1.2.3.4"], 60, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "FieldArrayMismatch")
			await expect(
				dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 0, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "InvalidTTL")
			await expect(
				dapp.connect(alice).setRecord("example", "A", "x".repeat(257), ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "SelectorTooLong")
		})

		it("rejects writes by non-owner / to unregistered or expired domains", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await expect(
				dapp.connect(bob).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "NotDomainOwner")
			await expect(
				dapp.connect(alice).setRecord("ghost", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "DomainNotRegistered")

			await time.increase(YEAR + 1n)
			await expect(
				dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "DomainExpired")
		})
	})

	describe("selector matching (UC-8)", () => {
		const SMTP_SEL = "port=25&service=SMTP&transport=TCP"
		const HTTP_SEL = "port=443&service=HTTP&transport=QUIC"

		it("distinguishes records of the same type by selector", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			const fields = ["target", "service", "transport", "port"]
			await dapp
				.connect(alice)
				.setRecord("example", "SVC", SMTP_SEL, fields, ["mail.example", "SMTP", "TCP", "25"], 300, SIG, NO_COMMIT)
			await dapp
				.connect(alice)
				.setRecord("example", "SVC", HTTP_SEL, fields, ["web.example", "HTTP", "QUIC", "443"], 300, SIG, NO_COMMIT)

			const smtp = await dapp.lookup("example", "SVC", SMTP_SEL)
			expect(smtp.exists).to.equal(true)
			expect(smtp.fieldValues[0]).to.equal("mail.example")

			const http = await dapp.lookup("example", "SVC", HTTP_SEL)
			expect(http.fieldValues[0]).to.equal("web.example")

			// typed "no match"
			const miss = await dapp.lookup("example", "SVC", "port=21&service=FTP&transport=TCP")
			expect(miss.exists).to.equal(false)
			expect(await dapp.listRecords("example")).to.have.length(2)
		})
	})

	describe("removeRecord", () => {
		it("removes and emits RecordRemoved", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT)
			await expect(dapp.connect(alice).removeRecord("example", "A", "")).to.emit(dapp, "RecordRemoved")
			expect((await dapp.lookup("example", "A", "")).exists).to.equal(false)
			expect(await dapp.listRecords("example")).to.have.length(0)
		})

		it("reverts for missing records and non-owners", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await expect(dapp.connect(alice).removeRecord("example", "A", "")).to.be.revertedWithCustomError(
				dapp,
				"RecordNotFound",
			)
			await dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT)
			await expect(dapp.connect(bob).removeRecord("example", "A", "")).to.be.revertedWithCustomError(
				dapp,
				"NotDomainOwner",
			)
		})
	})

	describe("generation semantics across expiry", () => {
		it("hides stale records after re-registration (UC-3 safety)", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT)

			await time.increase(YEAR + 1n)
			expect((await dapp.lookup("example", "A", "")).exists).to.equal(false)

			await commitAndRegister(dapp, bob, "example", PUBKEY2, BASE_PRICE)
			// bob's fresh domain: alice's record must be invisible
			expect((await dapp.lookup("example", "A", "")).exists).to.equal(false)
			expect(await dapp.listRecords("example")).to.have.length(0)

			// bob overwrites the same key
			await dapp.connect(bob).setRecord("example", "A", "", ["address"], ["9.9.9.9"], 60, SIG, NO_COMMIT)
			const rec = await dapp.lookup("example", "A", "")
			expect(rec.exists).to.equal(true)
			expect(rec.fieldValues).to.deep.equal(["9.9.9.9"])
			expect(await dapp.listRecords("example")).to.have.length(1)
		})

		it("hides the previous owner's records after transfer (UC-3 safety)", async () => {
			const { dapp, alice, bob } = await loadFixture(deployFixture)
			await dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT)
			expect((await dapp.lookup("example", "A", "")).exists).to.equal(true)

			// alice transfers to bob: her record was signed under her key and can
			// never verify against bob's, so the generation bump must make it
			// invisible — a resolver must not serve an unverifiable record.
			await dapp.connect(alice).transfer("example", bob.address, PUBKEY2)
			expect((await dapp.lookup("example", "A", "")).exists).to.equal(false)
			expect(await dapp.listRecords("example")).to.have.length(0)

			// bob re-creates the record under his key; now it resolves again.
			await dapp.connect(bob).setRecord("example", "A", "", ["address"], ["5.6.7.8"], 60, SIG, NO_COMMIT)
			const rec = await dapp.lookup("example", "A", "")
			expect(rec.exists).to.equal(true)
			expect(rec.fieldValues).to.deep.equal(["5.6.7.8"])
			expect(await dapp.listRecords("example")).to.have.length(1)
		})
	})

	describe("resolve()", () => {
		it("returns record plus owner identity in one call", async () => {
			const { dapp, alice } = await loadFixture(deployFixture)
			await dapp.connect(alice).setRecord("example", "A", "", ["address"], ["1.2.3.4"], 60, SIG, NO_COMMIT)
			const [record, owner, pubKey] = await dapp.resolve("example", "A", "")
			expect(record.exists).to.equal(true)
			expect(owner).to.equal(alice.address)
			expect(pubKey).to.equal(PUBKEY)
		})

		it("returns empty identity for expired domains", async () => {
			const { dapp } = await loadFixture(deployFixture)
			await time.increase(YEAR + 1n)
			const [record, owner, pubKey] = await dapp.resolve("example", "A", "")
			expect(record.exists).to.equal(false)
			expect(owner).to.equal(ethers.ZeroAddress)
			expect(pubKey).to.equal("0x")
		})
	})

	describe("dynamic type end-to-end (UC-9)", () => {
		it("declares GEO and stores a schema-validated GEO record", async () => {
			const { dapp, registry, alice } = await loadFixture(deployFixture)
			await registry.declareType("GEO", ["lat", "lon"], ["alt"])

			await expect(
				dapp.connect(alice).setRecord("example", "GEO", "", ["lat"], ["32.1"], 60, SIG, NO_COMMIT),
			).to.be.revertedWithCustomError(dapp, "MissingMandatoryField")

			await dapp
				.connect(alice)
				.setRecord("example", "GEO", "", ["lat", "lon", "alt"], ["32.1", "34.8", "120"], 60, SIG, NO_COMMIT)
			const rec = await dapp.lookup("example", "GEO", "")
			expect(rec.exists).to.equal(true)
			expect(rec.fieldValues).to.deep.equal(["32.1", "34.8", "120"])
		})
	})
})
