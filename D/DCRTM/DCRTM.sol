// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DYNAMIC CORE ROOT OF TRUST FOR MEASUREMENT DEMO
 * — Illustrates a naïve static root of trust vs. a dynamic chain‐of‐trust
 *   where each module measurement extends the core root.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — Vulnerable Static CRTM (⚠️ insecure)
----------------------------------------------------------------------------*/
contract VulnerableStaticCRTM {
    // A single static “root of trust” that never changes
    bytes32 public rootOfTrust;

    event StaticRootSet(bytes32 indexed root);

    /// Set the static root (no access control! can be overwritten by anyone)
    function setRootOfTrust(bytes32 _root) external {
        rootOfTrust = _root;
        emit StaticRootSet(_root);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers: Ownable
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not owner");
        _;
    }

    /// Transfer the owner (e.g. to a secure enclave)
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }

    function owner() public view returns (address) {
        return _owner;
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — Dynamic Core Root Of Trust For Measurement (✅ secure)
----------------------------------------------------------------------------*/
contract DynamicCRTM is Ownable {
    // The evolving root of trust, initially zero
    bytes32 public currentRoot;

    event RootInitialized(bytes32 indexed root);
    event ModuleMeasured(bytes32 indexed moduleHash, bytes32 indexed newRoot);

    /// @notice Initialize the root of trust (one‐time, by owner)
    function initializeRoot(bytes32 _initialRoot) external onlyOwner {
        require(currentRoot == bytes32(0), "CRTM: already initialized");
        currentRoot = _initialRoot;
        emit RootInitialized(_initialRoot);
    }

    /// @notice Measure a new module and extend the root: newRoot = H(currentRoot ∥ moduleHash)
    function measureModule(bytes32 moduleHash) external onlyOwner {
        require(currentRoot != bytes32(0), "CRTM: not initialized");
        bytes32 newRoot = keccak256(abi.encodePacked(currentRoot, moduleHash));
        currentRoot = newRoot;
        emit ModuleMeasured(moduleHash, newRoot);
    }

    /// @notice Convenience read of the current root
    function getCurrentRoot() external view returns (bytes32) {
        return currentRoot;
    }
}
