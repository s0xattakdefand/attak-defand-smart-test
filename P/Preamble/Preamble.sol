// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Function Selector Preamble Validator ========== */
contract SelectorPreambleCheck {
    bytes4 public constant VALID = bytes4(keccak256("claim()"));

    fallback() external {
        require(msg.sig == VALID, "Selector preamble blocked");
    }
}

/* ========== 2️⃣ Custom Magic Preamble ========== */
contract MagicPreambleGuard {
    bytes4 public magic = 0xdeadbeef;

    function execute(bytes calldata payload) external {
        bytes4 prefix;
        assembly {
            prefix := calldataload(payload.offset)
        }
        require(prefix == magic, "Bad preamble");
        // Execute rest...
    }
}

/* ========== 3️⃣ MetaTx Preamble Signature Check ========== */
contract MetaTxPreamble {
    function validate(bytes32 hash, bytes memory sig) external pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(hash, v, r, s);
    }
}

/* ========== 4️⃣ ZK Root Preamble (Mocked) ========== */
contract ZKRootCheck {
    bytes32 public validRoot;

    function setRoot(bytes32 r) external {
        validRoot = r;
    }

    function zkVerify(bytes32 preambleRoot) external view returns (bool) {
        return preambleRoot == validRoot;
    }
}

/* ========== 5️⃣ Route Prefix Preamble (Multi-Hop Bridge) ========== */
contract RouteHeader {
    struct Header {
        address from;
        address to;
        uint256 timestamp;
    }

    function checkHeader(bytes calldata input) external pure returns (Header memory) {
        Header memory h = abi.decode(input[:96], (address, address, uint256));
        return h;
    }
}
