// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   PCI DSS DEMO
   — Illustrates a vulnerable contract that stores raw PANs on‐chain vs. a
     PCI-compliant vault that only handles tokenized card data, enforces
     access control, and logs requests without exposing PANs.
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — PlainCardStore (⚠️ Vulnerable, NOT PCI DSS compliant)
   • Stores full Primary Account Numbers (PANs) in cleartext on-chain.
   • Emits PANs in events—forever public in logs.
   • No access control ⇒ any caller can read or overwrite.
----------------------------------------------------------------------------*/
contract PlainCardStore {
    mapping(address => string) public panStore;

    event PANStored(address indexed customer, string pan);

    /// Anyone can store their PAN in cleartext.
    function storePAN(string calldata pan) external {
        panStore[msg.sender] = pan;
        emit PANStored(msg.sender, pan);
    }

    /// Anyone can read any stored PAN.
    function getPAN(address customer) external view returns (string memory) {
        return panStore[customer];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers for PCICompliantVault
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: not owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

library ECDSA {
    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
    function recover(bytes32 h, bytes calldata sig) internal pure returns (address) {
        require(sig.length == 65, "ECDSA: bad sig length");
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        return ecrecover(toEthSignedMessageHash(h), v, r, s);
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — PCICompliantVault (✅ PCI DSS–style tokenization & controls)
   • Never stores raw PANs on-chain—only tokenized representations.
   • Only contract owner can tokenize cards and authorize readers.
   • Readers must obtain owner’s signed approval to request clear PAN off-chain.
   • Events log token registrations and access requests, but never PANs.
----------------------------------------------------------------------------*/
contract PCICompliantVault is Ownable {
    using ECDSA for bytes32;

    struct CardInfo {
        bytes32 token;           // off-chain token or surrogate for PAN
        uint256    timestamp;    // when token was recorded
    }

    // customer address ⇒ card token info
    mapping(address => CardInfo) private _cards;
    // reader ⇒ allowed to request clear PAN
    mapping(address => bool)    private _authorizedReaders;

    event CardTokenized(address indexed customer, bytes32 token, uint256 timestamp);
    event ReaderAuthorized(address indexed reader);
    event ClearPANRequested(address indexed requester, address indexed customer, bytes32 requestHash);

    /// Owner registers a card by storing only its token (e.g., via a PCI-approved service).
    function tokenizeCard(address customer, bytes32 token) external onlyOwner {
        _cards[customer] = CardInfo({ token: token, timestamp: block.timestamp });
        emit CardTokenized(customer, token, block.timestamp);
    }

    /// Owner authorizes an off-chain service or auditor to request clear PAN.
    function authorizeReader(address reader) external onlyOwner {
        _authorizedReaders[reader] = true;
        emit ReaderAuthorized(reader);
    }

    /// Anyone can fetch the token for a customer—no PAN exposure.
    function getToken(address customer) external view returns (bytes32 token, uint256 timestamp) {
        CardInfo storage info = _cards[customer];
        return (info.token, info.timestamp);
    }

    /**
     * Request the clear PAN for a customer.
     * Must supply a signature by the vault owner over (this contract, requester, customer).
     * Emits an event that a secure off-chain processor listens to in order to
     * deliver the actual PAN via a PCI-compliant channel.
     */
    function requestClearPAN(
        address customer,
        bytes calldata ownerSig
    ) external {
        require(_authorizedReaders[msg.sender], "Not an authorized reader");

        // Reconstruct the signed message
        bytes32 msgHash = keccak256(abi.encodePacked(address(this), msg.sender, customer));
        require(msgHash.recover(ownerSig) == owner(), "Invalid owner signature");

        emit ClearPANRequested(msg.sender, customer, msgHash);
    }
}
