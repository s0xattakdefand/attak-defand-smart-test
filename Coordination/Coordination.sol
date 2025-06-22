// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract CoordinationVault {
    address public owner;
    address[] public coordinators;
    uint256 public requiredApprovals;
    uint256 public currentNonce;

    mapping(uint256 => mapping(address => bool)) public approvedBy;
    mapping(uint256 => uint256) public approvalCount;

    event UnlockRequested(uint256 nonce, uint256 amount, address to);
    event Approved(address coordinator, uint256 nonce);
    event Executed(uint256 nonce, address to, uint256 amount);

    constructor(address[] memory _coordinators, uint256 _requiredApprovals) {
        require(_requiredApprovals <= _coordinators.length, "Too many required");
        owner = msg.sender;
        coordinators = _coordinators;
        requiredApprovals = _requiredApprovals;
    }

    modifier onlyCoordinator() {
        bool isCoord = false;
        for (uint256 i = 0; i < coordinators.length; i++) {
            if (msg.sender == coordinators[i]) {
                isCoord = true;
                break;
            }
        }
        require(isCoord, "Not coordinator");
        _;
    }

    function requestUnlock(address to, uint256 amount) external onlyCoordinator {
        emit UnlockRequested(currentNonce, amount, to);
    }

    function approve(uint256 nonce) external onlyCoordinator {
        require(!approvedBy[nonce][msg.sender], "Already approved");
        approvedBy[nonce][msg.sender] = true;
        approvalCount[nonce]++;
        emit Approved(msg.sender, nonce);
    }

    function execute(address payable to, uint256 amount, uint256 nonce) external onlyCoordinator {
        require(approvalCount[nonce] >= requiredApprovals, "Not enough approvals");
        require(nonce == currentNonce, "Invalid nonce");
        currentNonce++;
        to.transfer(amount);
        emit Executed(nonce, to, amount);
    }

    receive() external payable {}
}
