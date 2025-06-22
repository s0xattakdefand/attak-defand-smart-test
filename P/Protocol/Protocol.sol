// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

/* ========== 1️⃣ Financial Protocol Example ========== */
contract VaultProtocol {
    mapping(address => uint256) public deposits;

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw(uint256 amt) external {
        require(deposits[msg.sender] >= amt, "Not enough");
        deposits[msg.sender] -= amt;
        payable(msg.sender).transfer(amt);
    }
}

/* ========== 2️⃣ Governance Protocol ========== */
contract Governance {
    struct Proposal {
        string description;
        uint256 yes;
        uint256 no;
        bool executed;
    }

    Proposal[] public proposals;
    mapping(address => uint256) public votingPower;

    function propose(string calldata desc) external {
        proposals.push(Proposal(desc, 0, 0, false));
    }

    function vote(uint256 id, bool support) external {
        require(!proposals[id].executed, "Executed");
        if (support) proposals[id].yes += votingPower[msg.sender];
        else proposals[id].no += votingPower[msg.sender];
    }

    function execute(uint256 id) external {
        Proposal storage p = proposals[id];
        require(!p.executed && p.yes > p.no, "Failed");
        p.executed = true;
        // perform action
    }

    function stake() external payable {
        votingPower[msg.sender] += msg.value;
    }
}

/* ========== 3️⃣ Oracle Protocol ========== */
contract SimpleOracle {
    address public reporter;
    uint256 public price;

    constructor(address r) {
        reporter = r;
    }

    function report(uint256 p) external {
        require(msg.sender == reporter, "Not reporter");
        price = p;
    }
}

/* ========== 4️⃣ ZK Nullifier Checker (Mock) ========== */
contract ZKNullifier {
    mapping(bytes32 => bool) public used;

    function verify(bytes32 nullifier) external {
        require(!used[nullifier], "Replay");
        used[nullifier] = true;
        // do action
    }
}

/* ========== 5️⃣ Bridge Nonce Protocol ========== */
contract BridgeGuard {
    mapping(bytes32 => bool) public seen;

    function relay(bytes32 id, bytes calldata data) external {
        require(!seen[id], "Already relayed");
        seen[id] = true;
        // decode + execute
    }
}
