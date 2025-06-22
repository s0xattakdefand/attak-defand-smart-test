// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title CyberAttackSuite.sol
/// @notice On‑chain analogues of “Cyber Attack” patterns:
///   Types: DDoS, Phishing, Malware, ManInTheMiddle  
///   AttackTypes: VolumeAttack, CredentialTheft, PayloadInjection, SessionHijack  
///   DefenseTypes: RateLimit, MultiFactorAuth, AntivirusProtection, Encryption  

enum CyberAttackType         { DDoS, Phishing, Malware, ManInTheMiddle }
enum CyberAttackAttackType   { VolumeAttack, CredentialTheft, PayloadInjection, SessionHijack }
enum CyberAttackDefenseType  { RateLimit, MultiFactorAuth, AntivirusProtection, Encryption }

error CA__TooManyRequests();
error CA__NotAuthorized();
error CA__InvalidPayload();
error CA__NotEncrypted();

////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE: no controls, any caller may launch any attack
////////////////////////////////////////////////////////////////////////
contract CyberAttackVuln {
    event AttackLaunched(
        address indexed by,
        CyberAttackType        atype,
        bytes                  data,
        CyberAttackAttackType  attack
    );

    function launch(CyberAttackType atype, bytes calldata data) external {
        emit AttackLaunched(msg.sender, atype, data, CyberAttackAttackType.VolumeAttack);
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB: demonstrates flooding and spoofing
////////////////////////////////////////////////////////////////////////
contract Attack_CyberAttack {
    CyberAttackVuln public target;
    constructor(CyberAttackVuln _t) { target = _t; }

    /// flood many DDoS launches
    function flood(uint256 n) external {
        for (uint256 i = 0; i < n; i++) {
            target.launch(CyberAttackType.DDoS, "");
        }
    }

    /// spoof a session hijack payload
    function spoofSession(bytes calldata payload) external {
        target.launch(CyberAttackType.ManInTheMiddle, payload);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) SAFE RATE‑LIMIT: cap attacks per block
////////////////////////////////////////////////////////////////////////
contract CyberAttackSafeRateLimit {
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public countInBlock;
    uint256 public constant MAX_PER_BLOCK = 5;

    event AttackLaunched(
        address indexed by,
        CyberAttackType        atype,
        bytes                  data,
        CyberAttackDefenseType defense
    );

    function launch(CyberAttackType atype, bytes calldata data) external {
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            countInBlock[msg.sender] = 0;
        }
        countInBlock[msg.sender]++;
        if (countInBlock[msg.sender] > MAX_PER_BLOCK) revert CA__TooManyRequests();

        emit AttackLaunched(msg.sender, atype, data, CyberAttackDefenseType.RateLimit);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) SAFE MULTI‑FACTOR + ENCRYPTION: require MFA and encrypted payload
////////////////////////////////////////////////////////////////////////
contract CyberAttackSafeAuth {
    mapping(address => bool) public mfaPassed;
    event AttackLaunched(
        address indexed by,
        CyberAttackType        atype,
        bytes                  data,
        CyberAttackDefenseType defense
    );

    /// user completes MFA
    function authenticate() external {
        mfaPassed[msg.sender] = true;
    }

    /// only users who passed MFA can launch, and payload must be “encrypted” (first byte = 0x01)
    function launch(CyberAttackType atype, bytes calldata data) external {
        if (!mfaPassed[msg.sender])     revert CA__NotAuthorized();
        if (data.length == 0 || data[0] != 0x01) revert CA__NotEncrypted();

        emit AttackLaunched(msg.sender, atype, data, CyberAttackDefenseType.MultiFactorAuth);
    }
}
