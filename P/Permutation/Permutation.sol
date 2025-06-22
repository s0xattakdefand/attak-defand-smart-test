// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== PERMUTATION TYPES ========== */

// 1️⃣ Static Permutation
contract StaticPerm {
    function permute(uint256[] memory input) public pure returns (uint256[] memory) {
        uint256[] memory output = new uint256[](input.length);
        for (uint256 i = 0; i < input.length; i++) {
            output[i] = input[(i + 1) % input.length];
        }
        return output;
    }
}

// 2️⃣ Pseudo-Random Permutation
contract RandomShuffle {
    function shuffle(uint256[] memory arr, uint256 seed) public pure returns (uint256[] memory) {
        for (uint256 i = arr.length - 1; i > 0; i--) {
            uint256 j = uint256(keccak256(abi.encode(seed, i))) % (i + 1);
            (arr[i], arr[j]) = (arr[j], arr[i]);
        }
        return arr;
    }
}

// 3️⃣ Selector Permutation
contract PermuteSelectors {
    event Called(bytes4 selector, uint256 index);

    function callPermute(bytes4[] calldata selectors) external {
        for (uint i = 0; i < selectors.length; i++) {
            emit Called(selectors[i], i);
        }
    }
}

// 4️⃣ Hash-Based Permutation
contract HashPermute {
    function orderFromHash(bytes32 h, uint256 count) external pure returns (uint256[] memory) {
        uint256[] memory idx = new uint256[](count);
        for (uint256 i = 0; i < count; i++) idx[i] = i;
        for (uint256 i = count - 1; i > 0; i--) {
            uint256 j = uint256(keccak256(abi.encodePacked(h, i))) % (i + 1);
            (idx[i], idx[j]) = (idx[j], idx[i]);
        }
        return idx;
    }
}

/* ========== ATTACK SIMULATORS ========== */

// 1️⃣ Selector Mutation Drift
contract SelectorDrifter {
    function drift(bytes calldata data, address target) external {
        (bool ok, ) = target.call(data);
        require(ok);
    }
}

// 2️⃣ Batch Order Replayer
contract BatchOrderExploit {
    function executeBatch(address[] calldata targets, bytes[] calldata data) external {
        for (uint256 i = data.length; i > 0; i--) {
            targets[i - 1].call(data[i - 1]);
        }
    }
}

// 3️⃣ Oracle Leak via Perm Index
contract OracleLeak {
    uint256[] public prices;

    function set(uint256[] calldata vals) external {
        prices = vals;
    }

    function leak(uint i) external view returns (uint256) {
        return prices[i];
    }
}

// 4️⃣ Role Escalate Permute
contract RoleEscalator {
    address[] public admins;

    function patch(uint256 i, address who) external {
        require(i < admins.length);
        admins[i] = who;
    }
}

// 5️⃣ Drifted ZK Perm
contract DriftedZKProof {
    bytes32 public last;

    function fake(bytes calldata zk) external {
        last = keccak256(zk);
    }
}

/* ========== DEFENSE MODULES ========== */

// 🛡️ 1 Permutation Commit Guard
contract PermCommit {
    bytes32 public committed;

    function commit(uint256[] calldata input) external {
        committed = keccak256(abi.encode(input));
    }

    function verify(uint256[] calldata order) external view returns (bool) {
        return committed == keccak256(abi.encode(order));
    }
}

// 🛡️ 2 Randomness Verifier (mock)
contract VRFGuard {
    bytes32 public trustedEntropy;

    function setEntropy(bytes32 e) external {
        trustedEntropy = e;
    }

    function verify(bytes32 e) external view returns (bool) {
        return e == trustedEntropy;
    }
}

// 🛡️ 3 Role-Index Lock
contract RoleLock {
    mapping(uint256 => address) public atIndex;

    function assign(uint256 i, address who) external {
        require(atIndex[i] == address(0), "Locked");
        atIndex[i] = who;
    }
}

// 🛡️ 4 Selector Whitelist
contract SelectorPermit {
    mapping(bytes4 => bool) public permitted;

    function enable(bytes4 s, bool y) external {
        permitted[s] = y;
    }

    fallback() external {
        require(permitted[msg.sig], "Blocked");
    }
}

// 🛡️ 5 zkPermutation Proof Check (mock)
contract zkPermVerifier {
    bytes32 public validHash;

    function set(bytes32 h) external {
        validHash = h;
    }

    function verify(bytes calldata p) external view returns (bool) {
        return keccak256(p) == validHash;
    }
}
