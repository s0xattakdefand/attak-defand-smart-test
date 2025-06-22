// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 3-WAY HANDSHAKE FLOW ========== */
contract Handshake3Way {
    enum Phase { NONE, SYN, SYNACK, ACK }
    mapping(address => Phase) public state;
    mapping(address => uint256) public timestamp;

    event SYN_SENT(address indexed user);
    event SYNACK_SENT(address indexed server);
    event ACK_CONFIRMED(address indexed client);

    // 1️⃣ SYN Phase
    function initiateHandshake() external {
        require(state[msg.sender] == Phase.NONE, "Already initiated");
        state[msg.sender] = Phase.SYN;
        timestamp[msg.sender] = block.timestamp;
        emit SYN_SENT(msg.sender);
    }

    // 2️⃣ SYNACK Phase (e.g., server confirms)
    function respondToHandshake(address initiator) external {
        require(state[initiator] == Phase.SYN, "SYN not found");
        require(block.timestamp <= timestamp[initiator] + 30, "Handshake expired");
        state[initiator] = Phase.SYNACK;
        emit SYNACK_SENT(initiator);
    }

    // 3️⃣ ACK Phase (final ack by client)
    function confirmHandshake() external {
        require(state[msg.sender] == Phase.SYNACK, "Not at ACK phase");
        state[msg.sender] = Phase.ACK;
        emit ACK_CONFIRMED(msg.sender);
    }

    // Reset after ACK or timeout
    function reset(address user) external {
        if (state[user] == Phase.ACK || block.timestamp > timestamp[user] + 60) {
            state[user] = Phase.NONE;
        }
    }
}

/* ========== ATTACK MODULES ========== */
contract SYNFlood {
    function flood(address target, uint256 count) external {
        for (uint256 i = 0; i < count; i++) {
            Handshake3Way(target).initiateHandshake();
        }
    }
}

contract ACKSpoofer {
    function spoofACK(address target) external {
        Handshake3Way(target).confirmHandshake(); // skips SYN
    }
}

/* ========== DEFENSE MODULES ========== */

// 🛡️ Signature or ZK Validator
contract ACKValidator {
    mapping(address => bool) public seen;

    function confirm(bytes32 hash, bytes calldata sig) external {
        require(!seen[msg.sender], "Replay");
        seen[msg.sender] = true;
        address signer = recover(hash, sig);
        require(signer == msg.sender, "Invalid ACK signer");
    }

    function recover(bytes32 h, bytes memory sig) internal pure returns (address) {
        (bytes32 r, bytes32 s, uint8 v) = abi.decode(sig, (bytes32, bytes32, uint8));
        return ecrecover(h, v, r, s);
    }
}
