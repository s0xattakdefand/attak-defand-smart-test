// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Fallback Sniffer ========== */
contract PromiscuousSniffer {
    event Sniff(address from, bytes4 selector, uint256 value, bytes data);

    fallback() external payable {
        emit Sniff(msg.sender, msg.sig, msg.value, msg.data);
    }

    receive() external payable {
        emit Sniff(msg.sender, bytes4(0), msg.value, "");
    }
}

/* ========== 2️⃣ Proxy Call Logger ========== */
contract ProxyLogger {
    address public logic;

    constructor(address _logic) {
        logic = _logic;
    }

    fallback() external payable {
        emit Sniff(msg.sender, msg.sig, msg.value, msg.data);
        (bool ok, ) = logic.delegatecall(msg.data);
        require(ok);
    }

    event Sniff(address from, bytes4 selector, uint256 value, bytes data);
}

/* ========== 3️⃣ Event Watcher ========== */
interface TargetContract {
    function getLatestState() external view returns (string memory);
}

contract EventListener {
    event Copy(string value);

    function pull(address target) external {
        string memory data = TargetContract(target).getLatestState();
        emit Copy(data);
    }
}

/* ========== 4️⃣ Relay Interceptor ========== */
contract RelayTap {
    event RelayIntercepted(address user, bytes payload);

    function tap(bytes calldata payload) external {
        emit RelayIntercepted(msg.sender, payload);
        // Optionally forward
    }
}

/* ========== 5️⃣ ZKFilter Passive ========== */
contract PassiveZKReceiver {
    event ZKPayloadReceived(bytes32 root, string action);

    function receiveZK(bytes32 root, string calldata action) external {
        emit ZKPayloadReceived(root, action);
    }
}
