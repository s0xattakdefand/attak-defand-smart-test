// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

/**
 * @title DirectlyAttachedStorage (DAS)
 * @notice
 *   A minimal on-chain “directly attached storage” registry:
 *   users pay per-byte to store arbitrary data blobs on-chain,
 *   retrieve them by ID, update or delete their own entries,
 *   and the contract owner may withdraw collected fees.
 */
contract DirectlyAttachedStorage is Ownable, Pausable {
    struct Entry {
        address owner;
        bytes   data;
    }

    /// @dev fee in wei per byte of storage
    uint256 public feePerByte;

    /// @dev incremental ID counter
    uint256 private _nextId = 1;

    /// @dev storage mapping
    mapping(uint256 => Entry) private _entries;

    event DataStored   (uint256 indexed id, address indexed owner, uint256 size, uint256 feePaid);
    event DataUpdated  (uint256 indexed id, uint256 newSize, uint256 feePaid);
    event DataDeleted  (uint256 indexed id);
    event FeePerByteSet(uint256 newFee);

    /**
     * @param initialFeePerByte initial storage fee per byte (wei)
     */
    constructor(uint256 initialFeePerByte)
        Ownable(msg.sender)        // Initialize Ownable with deployer as owner
    {
        feePerByte = initialFeePerByte;
    }

    /// @notice Owner may update the per-byte storage fee
    function setFeePerByte(uint256 newFee) external onlyOwner {
        feePerByte = newFee;
        emit FeePerByteSet(newFee);
    }

    /// @notice Store a new blob on-chain; must pay `feePerByte * data.length`
    function storeData(bytes calldata data)
        external
        payable
        whenNotPaused
        returns (uint256 id)
    {
        uint256 size = data.length;
        uint256 required = size * feePerByte;
        require(msg.value == required, "DAS: incorrect fee");

        id = _nextId++;
        _entries[id] = Entry({ owner: msg.sender, data: data });

        emit DataStored(id, msg.sender, size, msg.value);
    }

    /// @notice Retrieve stored blob by ID
    function getData(uint256 id) external view returns (bytes memory) {
        Entry storage e = _entries[id];
        require(e.owner != address(0), "DAS: not found");
        return e.data;
    }

    /// @notice Update your blob; pay new fee based on new size
    function updateData(uint256 id, bytes calldata newData)
        external
        payable
        whenNotPaused
    {
        Entry storage e = _entries[id];
        require(e.owner == msg.sender, "DAS: not owner");

        uint256 newSize = newData.length;
        uint256 required = newSize * feePerByte;
        require(msg.value == required, "DAS: incorrect fee");

        e.data = newData;
        emit DataUpdated(id, newSize, msg.value);
    }

    /// @notice Delete your blob; no refund
    function deleteData(uint256 id) external whenNotPaused {
        Entry storage e = _entries[id];
        require(e.owner == msg.sender, "DAS: not owner");

        delete _entries[id];
        emit DataDeleted(id);
    }

    /// @notice Owner may withdraw accumulated fees
    function withdraw(address payable to) external onlyOwner {
        uint256 bal = address(this).balance;
        require(bal > 0, "DAS: no balance");
        to.transfer(bal);
    }

    /// @notice Pause storage operations in emergencies
    function pause() external onlyOwner {
        _pause();
    }

    /// @notice Unpause storage operations
    function unpause() external onlyOwner {
        _unpause();
    }
}
