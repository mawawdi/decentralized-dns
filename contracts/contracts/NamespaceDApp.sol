// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IRecordSchemaRegistry} from "./RecordSchemaRegistry.sol";

/// @title NamespaceDApp — on-chain authority for the Decentralized DNS.
/// @notice Manages namespace registration, renewal, ownership transfer, fee
///         collection (HLD §3.7, UC-1/UC-3) and the typed record store with
///         schema validation (UC-2, UC-8, UC-9).
/// @dev Domains are keyed by keccak256(name). Storage is intentionally
///      minimal: blockchain storage is expensive (HLD §2.2) — only
///      namespace metadata, record entries and content hashes live here.
contract NamespaceDApp {
    struct Domain {
        address owner; // current owner; address(0) == never registered
        bytes pubKey; // owner's public key, verified off-chain by resolvers
        uint64 expiry; // unix timestamp after which the name is re-registerable
        uint64 generation; // bumped on every (re-)registration; namespaces records
    }

    /// @notice Registration / renewal period.
    uint256 public constant REGISTRATION_PERIOD = 365 days;

    /// @notice Base yearly fee in wei for names of 5+ characters.
    ///         Shorter names cost more: 1 char x16, 2 x8, 3 x4, 4 x2.
    uint256 public immutable basePrice;

    /// @notice Account allowed to withdraw collected fees (the deployer).
    address public immutable treasurer;

    /// @notice Schema registry consulted on every record write (UC-9).
    IRecordSchemaRegistry public immutable registry;

    /// @dev Caps keeping every write-time loop strictly bounded (HLD §2.2).
    uint256 public constant MAX_RECORD_FIELDS = 16;
    uint256 public constant MAX_FIELD_NAME_LENGTH = 64;
    uint256 public constant MAX_FIELD_VALUE_LENGTH = 1024;
    uint256 public constant MAX_SELECTOR_LENGTH = 256;

    /// @notice A typed DNS record. Field semantics are defined by the
    ///         record-type schema in the RecordSchemaRegistry.
    struct Record {
        string recordType; // e.g. "A", "SVC", "ResourceRef", "GEO"
        string selector; // canonical selector, e.g. "port=25&service=SMTP&transport=TCP"
        string[] fieldNames;
        string[] fieldValues;
        uint32 ttl; // cache lifetime in seconds (HLD §3.3)
        uint64 generation; // domain generation at write time
        bytes ownerSig; // owner's signature over the canonical payload
        bytes32 commitment; // ZK commitment anchor (issues #8/#9)
        bool exists;
    }

    mapping(bytes32 => Domain) internal _domains;

    // nameHash => recordKey => Record
    mapping(bytes32 => mapping(bytes32 => Record)) private _records;
    // nameHash => generation => list of record keys written in that generation
    // (deduplicated). Scoped by generation — not just nameHash — so a
    // departing owner cannot grief a name: transfer/re-registration bumps the
    // generation and the new owner starts from a fresh, empty key list rather
    // than inheriting (and paying to iterate over, in listRecords) every
    // selector the previous owner ever wrote. The abandoned old-generation
    // array simply stops being referenced.
    mapping(bytes32 => mapping(uint64 => bytes32[])) private _recordKeys;
    // nameHash => generation => recordKey => index+1 into _recordKeys[..][generation] (0 = absent)
    mapping(bytes32 => mapping(uint64 => mapping(bytes32 => uint256))) private _recordKeyIndex;

    event Registered(
        bytes32 indexed nameHash,
        string name,
        address indexed owner,
        bytes pubKey,
        uint64 expiry,
        uint64 generation,
        uint256 feePaid
    );
    event Renewed(bytes32 indexed nameHash, uint64 newExpiry, uint256 feePaid);
    event Transferred(
        bytes32 indexed nameHash,
        address indexed oldOwner,
        address indexed newOwner,
        bytes newPubKey
    );
    event Withdrawn(address indexed to, uint256 amount);
    event RecordSet(
        bytes32 indexed nameHash,
        string name,
        bytes32 indexed recordKey,
        string recordType,
        string selector,
        uint32 ttl
    );
    event RecordRemoved(
        bytes32 indexed nameHash,
        string name,
        bytes32 indexed recordKey,
        string recordType,
        string selector
    );

    error InvalidName();
    error InvalidPubKey();
    error NameUnavailable();
    error DomainNotRegistered();
    error DomainExpired();
    error NotDomainOwner();
    error InsufficientFee(uint256 required, uint256 provided);
    error NotTreasurer();
    error ZeroAddress();
    error RefundFailed();
    error WithdrawFailed();
    error UnknownRecordType();
    error MissingMandatoryField(string field);
    error FieldArrayMismatch();
    error TooManyFields();
    error FieldValueTooLong();
    error FieldNameTooLong();
    error SelectorTooLong();
    error InvalidTTL();
    error RecordNotFound();

    constructor(uint256 _basePrice, IRecordSchemaRegistry _registry) {
        basePrice = _basePrice;
        treasurer = msg.sender;
        registry = _registry;
    }

    // ---------------------------------------------------------------- views

    /// @notice Yearly fee for `name` (length-based pricing).
    function priceOf(string calldata name) public view returns (uint256) {
        uint256 len = bytes(name).length;
        if (len == 0 || len > 63) revert InvalidName();
        if (len == 1) return basePrice * 16;
        if (len == 2) return basePrice * 8;
        if (len == 3) return basePrice * 4;
        if (len == 4) return basePrice * 2;
        return basePrice;
    }

    /// @notice True when `name` can be registered (never owned or expired).
    function available(string calldata name) public view returns (bool) {
        Domain storage d = _domains[keccak256(bytes(name))];
        return d.owner == address(0) || block.timestamp > d.expiry;
    }

    /// @notice Owner of an active domain; address(0) if free or expired.
    function ownerOf(string calldata name) external view returns (address) {
        Domain storage d = _domains[keccak256(bytes(name))];
        if (d.owner == address(0) || block.timestamp > d.expiry) {
            return address(0);
        }
        return d.owner;
    }

    /// @notice Raw domain state (also for expired domains; check `expiry`).
    function getDomain(
        string calldata name
    )
        external
        view
        returns (address owner, bytes memory pubKey, uint64 expiry, uint64 generation)
    {
        Domain storage d = _domains[keccak256(bytes(name))];
        return (d.owner, d.pubKey, d.expiry, d.generation);
    }

    // ------------------------------------------------------------- mutations

    /// @notice Register (or re-register an expired) `name`, paying the fee.
    /// @param name   the domain name: 1-63 chars of [a-z0-9-], no edge hyphen
    /// @param pubKey the owner's public key used by resolvers/clients to
    ///               verify record signatures (kept off-chain by the owner)
    function register(string calldata name, bytes calldata pubKey) external payable {
        _validateName(bytes(name));
        if (pubKey.length == 0 || pubKey.length > 128) revert InvalidPubKey();

        bytes32 h = keccak256(bytes(name));
        Domain storage d = _domains[h];
        if (d.owner != address(0) && block.timestamp <= d.expiry) {
            revert NameUnavailable();
        }

        uint256 price = priceOf(name);
        if (msg.value < price) revert InsufficientFee(price, msg.value);

        d.owner = msg.sender;
        d.pubKey = pubKey;
        d.expiry = uint64(block.timestamp + REGISTRATION_PERIOD);
        // Generation bump logically invalidates any records left behind by a
        // previous owner of the expired name (used by the record store).
        unchecked {
            d.generation += 1;
        }

        emit Registered(h, name, msg.sender, pubKey, d.expiry, d.generation, price);
        _refundExcess(price);
    }

    /// @notice Extend an active domain by one period. Anyone may pay.
    function renew(string calldata name) external payable {
        bytes32 h = keccak256(bytes(name));
        Domain storage d = _domains[h];
        if (d.owner == address(0)) revert DomainNotRegistered();
        if (block.timestamp > d.expiry) revert DomainExpired();

        uint256 price = priceOf(name);
        if (msg.value < price) revert InsufficientFee(price, msg.value);

        d.expiry = uint64(uint256(d.expiry) + REGISTRATION_PERIOD);

        emit Renewed(h, d.expiry, price);
        _refundExcess(price);
    }

    /// @notice Transfer an active domain, atomically rewriting owner and
    ///         pubKey (UC-3). The generation bump stops the previous owner's
    ///         records from resolving: they were signed under the old key and
    ///         can never verify against the new owner/pubKey. The new owner
    ///         re-creates (re-signs) any records they wish to keep.
    function transfer(
        string calldata name,
        address newOwner,
        bytes calldata newPubKey
    ) external {
        if (newOwner == address(0)) revert ZeroAddress();
        if (newPubKey.length == 0 || newPubKey.length > 128) revert InvalidPubKey();

        bytes32 h = keccak256(bytes(name));
        Domain storage d = _domains[h];
        if (d.owner == address(0)) revert DomainNotRegistered();
        if (block.timestamp > d.expiry) revert DomainExpired();
        if (msg.sender != d.owner) revert NotDomainOwner();

        address oldOwner = d.owner;
        d.owner = newOwner;
        d.pubKey = newPubKey;
        // Bump generation so the previous owner's records (signed under the
        // old key) immediately stop resolving and cannot be served as valid.
        unchecked {
            d.generation += 1;
        }

        emit Transferred(h, oldOwner, newOwner, newPubKey);
    }

    /// @notice Withdraw all collected fees to `to`. Treasurer only.
    function withdraw(address payable to) external {
        if (msg.sender != treasurer) revert NotTreasurer();
        if (to == address(0)) revert ZeroAddress();
        uint256 amount = address(this).balance;
        emit Withdrawn(to, amount);
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert WithdrawFailed();
    }

    // -------------------------------------------------------------- internal

    /// @dev Names: 1-63 bytes, [a-z0-9-], hyphen not at either edge.
    ///      The loop is bounded by 63 iterations (HLD determinism constraint).
    function _validateName(bytes memory b) internal pure {
        uint256 len = b.length;
        if (len == 0 || len > 63) revert InvalidName();
        if (b[0] == "-" || b[len - 1] == "-") revert InvalidName();
        for (uint256 i = 0; i < len; i++) {
            bytes1 c = b[i];
            bool ok = (c >= "a" && c <= "z") || (c >= "0" && c <= "9") || c == "-";
            if (!ok) revert InvalidName();
        }
    }

    /// @dev Refund any overpayment, after all state changes (CEI pattern).
    function _refundExcess(uint256 price) internal {
        uint256 excess = msg.value - price;
        if (excess > 0) {
            (bool ok, ) = payable(msg.sender).call{value: excess}("");
            if (!ok) revert RefundFailed();
        }
    }

    // ----------------------------------------------------------- record store

    /// @notice Deterministic storage key of a (recordType, selector) pair.
    function recordKeyOf(
        string calldata recordType,
        string calldata selector
    ) public pure returns (bytes32) {
        return
            keccak256(
                abi.encode(keccak256(bytes(recordType)), keccak256(bytes(selector)))
            );
    }

    /// @notice Create or overwrite a record (UC-2). Only the domain owner of
    ///         an active domain. The record type must be declared in the
    ///         schema registry and carry every mandatory field (UC-9).
    /// @param ownerSig   owner's signature over the canonical record payload,
    ///                   verified off-chain by resolvers and clients
    /// @param commitment MiMC commitment over the payload (ZK anchor); may be
    ///                   zero until the ZK pipeline is in use
    function setRecord(
        string calldata name,
        string calldata recordType,
        string calldata selector,
        string[] calldata fieldNames,
        string[] calldata fieldValues,
        uint32 ttl,
        bytes calldata ownerSig,
        bytes32 commitment
    ) external {
        bytes32 h = keccak256(bytes(name));
        Domain storage d = _domains[h];
        if (d.owner == address(0)) revert DomainNotRegistered();
        if (block.timestamp > d.expiry) revert DomainExpired();
        if (msg.sender != d.owner) revert NotDomainOwner();

        if (fieldNames.length != fieldValues.length) revert FieldArrayMismatch();
        if (fieldNames.length > MAX_RECORD_FIELDS) revert TooManyFields();
        if (bytes(selector).length > MAX_SELECTOR_LENGTH) revert SelectorTooLong();
        if (ttl == 0) revert InvalidTTL();
        for (uint256 i = 0; i < fieldValues.length; i++) {
            if (bytes(fieldNames[i]).length > MAX_FIELD_NAME_LENGTH) {
                revert FieldNameTooLong();
            }
            if (bytes(fieldValues[i]).length > MAX_FIELD_VALUE_LENGTH) {
                revert FieldValueTooLong();
            }
        }

        bytes32 typeHash = keccak256(bytes(recordType));
        if (!registry.typeExists(recordType)) revert UnknownRecordType();
        _checkMandatoryFields(typeHash, fieldNames);

        bytes32 key = recordKeyOf(recordType, selector);
        Record storage r = _records[h][key];
        r.recordType = recordType;
        r.selector = selector;
        r.fieldNames = fieldNames;
        r.fieldValues = fieldValues;
        r.ttl = ttl;
        r.generation = d.generation;
        r.ownerSig = ownerSig;
        r.commitment = commitment;
        r.exists = true;

        if (_recordKeyIndex[h][d.generation][key] == 0) {
            _recordKeys[h][d.generation].push(key);
            _recordKeyIndex[h][d.generation][key] = _recordKeys[h][d.generation].length; // index + 1
        }

        emit RecordSet(h, name, key, recordType, selector, ttl);
    }

    /// @notice Remove a record. Only the domain owner of an active domain.
    function removeRecord(
        string calldata name,
        string calldata recordType,
        string calldata selector
    ) external {
        bytes32 h = keccak256(bytes(name));
        Domain storage d = _domains[h];
        if (d.owner == address(0)) revert DomainNotRegistered();
        if (block.timestamp > d.expiry) revert DomainExpired();
        if (msg.sender != d.owner) revert NotDomainOwner();

        bytes32 key = recordKeyOf(recordType, selector);
        Record storage r = _records[h][key];
        if (!r.exists || r.generation != d.generation) revert RecordNotFound();

        delete _records[h][key];
        uint256 idxPlus1 = _recordKeyIndex[h][d.generation][key];
        bytes32[] storage keys = _recordKeys[h][d.generation];
        uint256 lastIdx = keys.length - 1;
        if (idxPlus1 - 1 != lastIdx) {
            bytes32 moved = keys[lastIdx];
            keys[idxPlus1 - 1] = moved;
            _recordKeyIndex[h][d.generation][moved] = idxPlus1;
        }
        keys.pop();
        delete _recordKeyIndex[h][d.generation][key];

        emit RecordRemoved(h, name, key, recordType, selector);
    }

    /// @notice Exact-match lookup (HLD §3.4: lookup(domain, type, selector)).
    ///         Returns exists=false for free/expired domains and for records
    ///         from a previous registration generation.
    function lookup(
        string calldata name,
        string calldata recordType,
        string calldata selector
    ) public view returns (Record memory record) {
        bytes32 h = keccak256(bytes(name));
        Domain storage d = _domains[h];
        if (d.owner == address(0) || block.timestamp > d.expiry) {
            return record; // exists=false
        }
        Record storage r = _records[h][recordKeyOf(recordType, selector)];
        if (!r.exists || r.generation != d.generation) {
            return record; // exists=false
        }
        return r;
    }

    /// @notice Combined lookup returning the record plus the domain identity
    ///         needed by resolvers to verify the owner signature in one call.
    function resolve(
        string calldata name,
        string calldata recordType,
        string calldata selector
    )
        external
        view
        returns (Record memory record, address owner, bytes memory pubKey)
    {
        record = lookup(name, recordType, selector);
        Domain storage d = _domains[keccak256(bytes(name))];
        if (d.owner != address(0) && block.timestamp <= d.expiry) {
            owner = d.owner;
            pubKey = d.pubKey;
        }
    }

    /// @notice All live records of an active domain (current generation).
    ///         View-only enumeration; loops are off-chain gas-free. The key
    ///         list is scoped to the current generation, so a previous
    ///         owner's records (however many selectors they wrote) can never
    ///         inflate this loop for the current owner.
    function listRecords(
        string calldata name
    ) external view returns (Record[] memory out) {
        bytes32 h = keccak256(bytes(name));
        Domain storage d = _domains[h];
        if (d.owner == address(0) || block.timestamp > d.expiry) {
            return new Record[](0);
        }
        bytes32[] storage keys = _recordKeys[h][d.generation];
        uint256 live = 0;
        for (uint256 i = 0; i < keys.length; i++) {
            Record storage r = _records[h][keys[i]];
            if (r.exists && r.generation == d.generation) live++;
        }
        out = new Record[](live);
        uint256 j = 0;
        for (uint256 i = 0; i < keys.length; i++) {
            Record storage r = _records[h][keys[i]];
            if (r.exists && r.generation == d.generation) out[j++] = r;
        }
    }

    /// @dev Every mandatory field of the schema must appear in fieldNames.
    ///      Bounded by MAX_FIELDS^2 = 256 iterations.
    function _checkMandatoryFields(
        bytes32 typeHash,
        string[] calldata fieldNames
    ) private view {
        string[] memory mandatory = registry.mandatoryFields(typeHash);
        for (uint256 i = 0; i < mandatory.length; i++) {
            bytes32 want = keccak256(bytes(mandatory[i]));
            bool found = false;
            for (uint256 j = 0; j < fieldNames.length; j++) {
                if (keccak256(bytes(fieldNames[j])) == want) {
                    found = true;
                    break;
                }
            }
            if (!found) revert MissingMandatoryField(mandatory[i]);
        }
    }
}
