// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title SubnetMaskSuite.sol
/// @notice Four on‑chain “Subnet Mask” patterns illustrating common pitfalls
///         and hardened defenses.

error SM__BadPrefix();
error SM__NotOwner();
error SM__BulkTooLarge();
error SM__Overlap();

/// @dev simple library for mask operations
library SubnetLib {
    /// @notice compute network address given IP and prefix
    function computeNetwork(uint32 ip, uint8 prefix) internal pure returns (uint32) {
        return ip & (uint32(type(uint32).max) << (32 - prefix));
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 1) PREFIX RANGE VALIDATION
///
/// Vulnerable: no check on prefix → shift >=32 underflows or yields zero mask
/// Attack: call with prefix > 32, leading to invalid network addresses
/// Defense: require 0 ≤ prefix ≤ 32
///─────────────────────────────────────────────────────────────────────────────
contract PrefixRangeVuln {
    using SubnetLib for uint32;

    function network(uint32 ip, uint8 prefix) external pure returns (uint32) {
        // ❌ no validation
        return SubnetLib.computeNetwork(ip, prefix);
    }
}

contract Attack_PrefixRange {
    PrefixRangeVuln public target;
    constructor(PrefixRangeVuln _t) { target = _t; }
    function testOverflow(uint32 ip) external view returns (uint32) {
        // prefix = 40 > 32
        return target.network(ip, 40);
    }
}

contract PrefixRangeSafe {
    using SubnetLib for uint32;

    error SM__PrefixOutOfRange();

    function network(uint32 ip, uint8 prefix) external pure returns (uint32) {
        if (prefix > 32) revert SM__BadPrefix();
        return SubnetLib.computeNetwork(ip, prefix);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 2) SUBNET REGISTRY (ACL STYLE)
///
/// Vulnerable: anyone can register or override any subnet
/// Attack: hijack victim’s subnet assignment
/// Defense: only owner may register
///─────────────────────────────────────────────────────────────────────────────
contract SubnetRegistryVuln {
    struct Subnet { uint32 network; uint8 prefix; }
    mapping(uint256 => Subnet) public subnets;
    uint256 public count;

    function register(uint32 network_, uint8 prefix_) external {
        subnets[count++] = Subnet(network_, prefix_);
    }
}

contract Attack_SubnetRegistry {
    SubnetRegistryVuln public target;
    constructor(SubnetRegistryVuln _t) { target = _t; }
    function hijack(uint32 network_, uint8 prefix_) external {
        target.register(network_, prefix_);
    }
}

contract SubnetRegistrySafe {
    struct Subnet { uint32 network; uint8 prefix; }
    mapping(uint256 => Subnet) public subnets;
    uint256 public count;
    address public immutable owner;

    event Registered(uint32 network, uint8 prefix);

    constructor() {
        owner = msg.sender;
    }

    function register(uint32 network_, uint8 prefix_) external {
        if (msg.sender != owner) revert SM__NotOwner();
        if (prefix_ > 32)    revert SM__BadPrefix();
        subnets[count++] = Subnet(network_, prefix_);
        emit Registered(network_, prefix_);
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 3) BULK SUBNET CHECK
///
/// Vulnerable: unbounded array → DOS by passing huge list
/// Attack: pass massive list to consume all gas
/// Defense: enforce MAX_BULK
///─────────────────────────────────────────────────────────────────────────────
contract BulkSubnetCheckVuln {
    using SubnetLib for uint32;

    /// check each IP against given subnet
    function inSubnetBulk(
        uint32[] calldata ips,
        uint32  network_,
        uint8   prefix_
    ) external pure returns (bool[] memory) {
        bool[] memory results = new bool[](ips.length);
        uint32 mask = uint32(type(uint32).max) << (32 - prefix_);
        for (uint i; i < ips.length; i++) {
            results[i] = (ips[i] & mask) == (network_ & mask);
        }
        return results;
    }
}

contract Attack_BulkSubnetCheck {
    BulkSubnetCheckVuln public target;
    constructor(BulkSubnetCheckVuln _t) { target = _t; }

    function flood(uint32[] calldata ips, uint32 net, uint8 pre) external view returns (bool[] memory) {
        return target.inSubnetBulk(ips, net, pre);
    }
}

contract BulkSubnetCheckSafe {
    using SubnetLib for uint32;

    uint256 public constant MAX_BULK = 100;

    function inSubnetBulk(
        uint32[] calldata ips,
        uint32  network_,
        uint8   prefix_
    ) external pure returns (bool[] memory) {
        if (ips.length > MAX_BULK) revert SM__BulkTooLarge();
        bool[] memory results = new bool[](ips.length);
        uint32 mask = uint32(type(uint32).max) << (32 - prefix_);
        for (uint i; i < ips.length; i++) {
            results[i] = (ips[i] & mask) == (network_ & mask);
        }
        return results;
    }
}

///─────────────────────────────────────────────────────────────────────────────
/// 4) SUBNET OVERLAP DETECTION
///
/// Vulnerable: overlapping subnets may be registered → unintended access
/// Attack: define 10.0.0.0/8 and 10.0.1.0/24 → overlap
/// Defense: reject any new subnet that overlaps existing
///─────────────────────────────────────────────────────────────────────────────
contract SubnetOverlapVuln {
    struct Subnet { uint32 network; uint8 prefix; }
    Subnet[] public subnets;

    function add(uint32 network_, uint8 prefix_) external {
        subnets.push(Subnet(network_, prefix_));
    }
}

contract SubnetOverlapSafe {
    struct Subnet { uint32 network; uint8 prefix; }
    Subnet[] public subnets;

    error SM__OverlapDetected();

    function add(uint32 network_, uint8 prefix_) external {
        if (prefix_ > 32) revert SM__BadPrefix();
        uint32 maskNew = uint32(type(uint32).max) << (32 - prefix_);
        uint32 netNew  = network_ & maskNew;
        for (uint i; i < subnets.length; i++) {
            Subnet memory s = subnets[i];
            uint32 maskOld = uint32(type(uint32).max) << (32 - s.prefix);
            uint32 netOld  = s.network & maskOld;
            // overlap if one network falls within the other
            if ((netNew & maskOld) == netOld || (netOld & maskNew) == netNew) {
                revert SM__Overlap();
            }
        }
        subnets.push(Subnet(netNew, prefix_));
    }
}
