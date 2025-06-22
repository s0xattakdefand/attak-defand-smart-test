// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrintController {
    address public owner;
    uint256 public counter;
    string public systemStatus;

    event Printed(string indexed label, string message, uint256 timestamp);
    event Snapshot(uint256 indexed count, string status, address caller);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        systemStatus = "Initialized";
    }

    function increment() external {
        counter++;
    }

    function updateStatus(string calldata newStatus) external onlyOwner {
        systemStatus = newStatus;
    }

    /// ✅ Control-P: Print log with a message
    function printLog(string calldata label, string calldata message) external onlyOwner {
        emit Printed(label, message, block.timestamp);
    }

    /// ✅ Control-P: View output (getter)
    function printStatus() external view returns (uint256 count, string memory status) {
        return (counter, systemStatus);
    }

    /// ✅ Control-P: Emit snapshot report
    function reportSnapshot() external {
        emit Snapshot(counter, systemStatus, msg.sender);
    }
}
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract PrintController {
    address public owner;
    uint256 public counter;
    string public systemStatus;

    event Printed(string indexed label, string message, uint256 timestamp);
    event Snapshot(uint256 indexed count, string status, address caller);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
        systemStatus = "Initialized";
    }

    function increment() external {
        counter++;
    }

    function updateStatus(string calldata newStatus) external onlyOwner {
        systemStatus = newStatus;
    }

    /// ✅ Control-P: Print log with a message
    function printLog(string calldata label, string calldata message) external onlyOwner {
        emit Printed(label, message, block.timestamp);
    }

    /// ✅ Control-P: View output (getter)
    function printStatus() external view returns (uint256 count, string memory status) {
        return (counter, systemStatus);
    }

    /// ✅ Control-P: Emit snapshot report
    function reportSnapshot() external {
        emit Snapshot(counter, systemStatus, msg.sender);
    }
}
