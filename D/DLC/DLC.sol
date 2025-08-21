// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Discreet Log Contract (DLC) for Ethereum
contract DLC {
    // Struct to store DLC details
    struct Contract {
        address partyA;
        address partyB;
        uint256 amountA;
        uint256 amountB;
        bytes32 outcomeHash;
        uint256 expiry;
        bool settled;
        address oracle;
    }

    // Mapping to store contracts by ID
    mapping(bytes32 => Contract) public contracts;

    // Event emitted when a DLC is created
    event DLCCreated(bytes32 indexed contractId, address partyA, address partyB, address oracle);

    // Event emitted when a DLC is funded
    event DLCFunded(bytes32 indexed contractId, address funder, uint256 amount);

    // Event emitted when a DLC is settled
    event DLCSettled(bytes32 indexed contractId, address winner, uint256 amount);

    // Event emitted when a DLC is refunded
    event DLCRefunded(bytes32 indexed contractId, address party, uint256 amount);

    // Modifier to check if contract exists and is not settled
    modifier onlyActiveContract(bytes32 contractId) {
        require(contracts[contractId].partyA != address(0), "Contract does not exist");
        require(!contracts[contractId].settled, "Contract already settled");
        _;
    }

    // Create a new DLC
    function createDLC(
        address partyB,
        bytes32 outcomeHash,
        address oracle,
        uint256 expiry
    ) external payable returns (bytes32) {
        require(partyB != address(0), "Invalid partyB address");
        require(oracle != address(0), "Invalid oracle address");
        require(msg.value > 0, "Must send funds");
        require(expiry > block.timestamp, "Invalid expiry time");

        bytes32 contractId = keccak256(abi.encodePacked(msg.sender, partyB, outcomeHash, block.timestamp));
        Contract storage dlc = contracts[contractId];
        
        require(dlc.partyA == address(0), "Contract ID already exists");

        dlc.partyA = msg.sender;
        dlc.partyB = partyB;
        dlc.amountA = msg.value;
        dlc.outcomeHash = outcomeHash;
        dlc.oracle = oracle;
        dlc.expiry = expiry;
        dlc.settled = false;

        emit DLCCreated(contractId, msg.sender, partyB, oracle);
        emit DLCFunded(contractId, msg.sender, msg.value);

        return contractId;
    }

    // Party B funds the DLC
    function fundDLC(bytes32 contractId) external payable onlyActiveContract(contractId) {
        Contract storage dlc = contracts[contractId];
        require(msg.sender == dlc.partyB, "Only partyB can fund");
        require(msg.value > 0, "Must send funds");
        require(dlc.amountB == 0, "Already funded by partyB");

        dlc.amountB = msg.value;
        emit DLCFunded(contractId, msg.sender, msg.value);
    }

    // Settle the DLC based on oracle's signed outcome
    function settleDLC(bytes32 contractId, bytes32 outcome, bytes memory oracleSignature) 
        external 
        onlyActiveContract(contractId) 
    {
        Contract storage dlc = contracts[contractId];
        require(block.timestamp < dlc.expiry, "Contract expired");
        require(dlc.amountA > 0 && dlc.amountB > 0, "Contract not fully funded");

        // Verify oracle signature
        address signer = recoverSigner(outcome, oracleSignature);
        require(signer == dlc.oracle, "Invalid oracle signature");

        // Verify outcome matches the committed hash
        require(keccak256(abi.encodePacked(outcome)) == dlc.outcomeHash, "Invalid outcome");

        dlc.settled = true;

        // Determine winner based on outcome (simplified: outcome == hash(party address) wins)
        address winner = keccak256(abi.encodePacked(dlc.partyA)) == outcome ? dlc.partyA : dlc.partyB;
        uint256 totalAmount = dlc.amountA + dlc.amountB;

        payable(winner).transfer(totalAmount);
        emit DLCSettled(contractId, winner, totalAmount);
    }

    // Refund if contract expires or is not fully funded
    function refundDLC(bytes32 contractId) external onlyActiveContract(contractId) {
        Contract storage dlc = contracts[contractId];
        require(block.timestamp >= dlc.expiry, "Contract not expired");
        require(msg.sender == dlc.partyA || msg.sender == dlc.partyB, "Not a party");

        dlc.settled = true;

        if (dlc.amountA > 0) {
            payable(dlc.partyA).transfer(dlc.amountA);
            emit DLCRefunded(contractId, dlc.partyA, dlc.amountA);
        }
        if (dlc.amountB > 0) {
            payable(dlc.partyB).transfer(dlc.amountB);
            emit DLCRefunded(contractId, dlc.partyB, dlc.amountB);
        }
    }

    // Helper function to recover signer from signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) 
        internal 
        pure 
        returns (address) 
    {
        require(signature.length == 65, "Invalid signature length");

        bytes32 r;
        bytes32 s;
        uint8 v;

        assembly {
            r := mload(add(signature, 32))
            s := mload(add(signature, 64))
            v := byte(0, mload(add(signature, 96)))
        }

        if (v < 27) {
            v += 27;
        }

        require(v == 27 || v == 28, "Invalid signature 'v' value");
        return ecrecover(messageHash, v, r, s);
    }

    // Get contract details
    function getContractDetails(bytes32 contractId) 
        external 
        view 
        returns (address, address, uint256, uint256, bytes32, uint256, bool, address) 
    {
        Contract memory dlc = contracts[contractId];
        return (dlc.partyA, dlc.partyB, dlc.amountA, dlc.amountB, dlc.outcomeHash, dlc.expiry, dlc.settled, dlc.oracle);
    }

    // Prevent accidental ETH deposits
    receive() external payable {
        revert("Contract does not accept direct ETH");
    }
}