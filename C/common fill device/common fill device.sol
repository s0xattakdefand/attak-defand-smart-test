// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CommonFillDevice {
    address public admin;

    struct FillEntry {
        bytes32 keyHash;        // keccak256(publicKey or sharedKey)
        uint256 filledAt;
        address filledBy;
    }

    mapping(uint256 => FillEntry) public slots;
    mapping(address => bool) public authorizedFillers;

    event KeyFilled(uint256 indexed slot, address indexed by, bytes32 keyHash);
    event FillerAuthorized(address filler);
    event FillerRevoked(address filler);

    modifier onlyAdmin() {
        require(msg.sender == admin, "CFD: Not admin");
        _;
    }

    modifier onlyFiller() {
        require(authorizedFillers[msg.sender], "CFD: Not authorized filler");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function authorizeFiller(address filler) external onlyAdmin {
        authorizedFillers[filler] = true;
        emit FillerAuthorized(filler);
    }

    function revokeFiller(address filler) external onlyAdmin {
        authorizedFillers[filler] = false;
        emit FillerRevoked(filler);
    }

    function fillSlot(uint256 slotId, bytes32 keyHash) external onlyFiller {
        require(slots[slotId].filledAt == 0, "CFD: Slot already filled");

        slots[slotId] = FillEntry({
            keyHash: keyHash,
            filledAt: block.timestamp,
            filledBy: msg.sender
        });

        emit KeyFilled(slotId, msg.sender, keyHash);
    }

    function verifySlot(uint256 slotId, bytes32 checkHash) external view returns (bool) {
        return slots[slotId].keyHash == checkHash;
    }

    function getSlot(uint256 slotId) external view returns (bytes32 keyHash, uint256 filledAt, address filledBy) {
        FillEntry memory f = slots[slotId];
        return (f.keyHash, f.filledAt, f.filledBy);
    }
}
