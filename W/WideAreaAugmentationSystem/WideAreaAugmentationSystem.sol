// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title WideAreaAugmentationSystemSuite.sol
/// @notice On‐chain analogues of “Wide Area Augmentation System” (WAAS) patterns:
///   Types: SatelliteBased, GroundStationBased, AircraftBased, Hybrid  
///   AttackTypes: Spoofing, Jamming, Meaconing, DataCorruption  
///   DefenseTypes: Encryption, SignalAuthentication, Redundancy, Monitoring  

enum WideAreaAugmentationSystemType        { SatelliteBased, GroundStationBased, AircraftBased, Hybrid }
enum WideAreaAugmentationSystemAttackType  { Spoofing, Jamming, Meaconing, DataCorruption }
enum WideAreaAugmentationSystemDefenseType { Encryption, SignalAuthentication, Redundancy, Monitoring }

error WAA__NoKey();
error WAA__InvalidSignature();
error WAA__TooManyRequests();
error WAA__NotAuthorized();

////////////////////////////////////////////////////////////////////////////////
// 1) VULNERABLE WAAS BROADCASTER
//    • ❌ no integrity or source check → Spoofing, DataCorruption
////////////////////////////////////////////////////////////////////////////////
contract WAASVuln {
    mapping(uint256 => bytes) public corrections; // regionId → correction data
    event CorrectionBroadcast(
        address indexed who,
        uint256                regionId,
        bytes                  data,
        WideAreaAugmentationSystemType    atype,
        WideAreaAugmentationSystemAttackType attack
    );

    function broadcastCorrection(
        uint256 regionId,
        bytes calldata data,
        WideAreaAugmentationSystemType atype
    ) external {
        corrections[regionId] = data;
        emit CorrectionBroadcast(
            msg.sender,
            regionId,
            data,
            atype,
            WideAreaAugmentationSystemAttackType.Spoofing
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// 2) ATTACK STUB
//    • simulates jamming and meaconing of WAAS signals
////////////////////////////////////////////////////////////////////////////////
contract Attack_WAAS {
    WAASVuln public target;
    uint256 public lastRegion;
    bytes public  lastData;

    constructor(WAASVuln _t) {
        target = _t;
    }

    function jam(uint256 regionId) external {
        // override with empty payload to simulate jamming
        target.broadcastCorrection(regionId, "", WideAreaAugmentationSystemType.SatelliteBased);
    }

    function meacon(uint256 regionId, bytes calldata spoofed) external {
        // replay or replay with altered data
        target.broadcastCorrection(regionId, spoofed, WideAreaAugmentationSystemType.Hybrid);
    }

    function capture(uint256 regionId) external {
        lastRegion = regionId;
        lastData = target.corrections(regionId);
    }

    function replay() external {
        target.broadcastCorrection(lastRegion, lastData, WideAreaAugmentationSystemType.GroundStationBased);
    }
}

////////////////////////////////////////////////////////////////////////////////
// 3) SAFE WAAS WITH ENCRYPTION
//    • ✅ Defense: Encryption – payloads encrypted with region‐specific key
////////////////////////////////////////////////////////////////////////////////
contract WAASSafeEncryption {
    mapping(uint256 => bytes) private corrections;
    mapping(uint256 => bytes32) public regionKey; // regionId → AES key hash

    event CorrectionBroadcast(
        address indexed who,
        uint256                regionId,
        bytes                  ciphertext,
        WideAreaAugmentationSystemDefenseType defense
    );

    error WAA__NoKey();

    function setRegionKey(uint256 regionId, bytes32 keyHash) external {
        // in practice, only admin would call
        regionKey[regionId] = keyHash;
    }

    function broadcastCorrection(
        uint256 regionId,
        bytes calldata ciphertext
    ) external {
        require(regionKey[regionId] != bytes32(0), "no key");
        corrections[regionId] = ciphertext;
        emit CorrectionBroadcast(
            msg.sender,
            regionId,
            ciphertext,
            WideAreaAugmentationSystemDefenseType.Encryption
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// 4) SAFE WAAS WITH SIGNAL AUTHENTICATION
//    • ✅ Defense: SignalAuthentication – require authority’s signature
////////////////////////////////////////////////////////////////////////////////
contract WAASSafeAuth {
    address public authority;
    mapping(uint256 => bytes) public corrections;

    event CorrectionBroadcast(
        address indexed who,
        uint256                regionId,
        bytes                  data,
        WideAreaAugmentationSystemDefenseType defense
    );

    error WAA__InvalidSignature();

    constructor(address _authority) {
        authority = _authority;
    }

    function broadcastCorrection(
        uint256 regionId,
        bytes calldata data,
        bytes calldata sig
    ) external {
        // verify signature over (regionId||data)
        bytes32 msgHash = keccak256(abi.encodePacked(regionId, data));
        bytes32 ethMsg  = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", msgHash));
        (uint8 v, bytes32 r, bytes32 s) = abi.decode(sig, (uint8,bytes32,bytes32));
        if (ecrecover(ethMsg, v, r, s) != authority) revert WAA__InvalidSignature();

        corrections[regionId] = data;
        emit CorrectionBroadcast(
            msg.sender,
            regionId,
            data,
            WideAreaAugmentationSystemDefenseType.SignalAuthentication
        );
    }
}

////////////////////////////////////////////////////////////////////////////////
// 5) SAFE WAAS WITH REDUNDANCY & MONITORING
//    • ✅ Defense: Redundancy – require N-of-M broadcasts  
//               Monitoring – rate-limit and alert anomalies
////////////////////////////////////////////////////////////////////////////////
contract WAASSafeAdvanced {
    struct Broadcast {
        bytes   data;
        uint256 count;
        mapping(address=>bool) voted;
    }
    mapping(uint256 => Broadcast) public broadcasts; // regionId → aggregated
    mapping(address => uint256) public lastBlock;
    mapping(address => uint256) public callsInBlock;
    uint256 public constant MAX_CALLS = 5;
    address[] public broadcasters;
    uint256 public threshold;

    event CorrectionCommit(
        uint256 regionId,
        bytes   data,
        WideAreaAugmentationSystemDefenseType defense
    );
    event Anomaly(
        address indexed who,
        string            reason,
        WideAreaAugmentationSystemDefenseType defense
    );

    error WAA__TooManyRequests();
    error WAA__NotAuthorized();

    constructor(address[] memory _broadcasters, uint256 _threshold) {
        require(_broadcasters.length >= _threshold, "threshold too high");
        broadcasters = _broadcasters;
        threshold = _threshold;
    }

    function isAuthorized(address who) internal view returns(bool) {
        for (uint i; i < broadcasters.length; i++) {
            if (broadcasters[i] == who) return true;
        }
        return false;
    }

    function broadcastCorrection(uint256 regionId, bytes calldata data) external {
        // rate-limit
        if (block.number != lastBlock[msg.sender]) {
            lastBlock[msg.sender]    = block.number;
            callsInBlock[msg.sender] = 0;
        }
        callsInBlock[msg.sender]++;
        if (callsInBlock[msg.sender] > MAX_CALLS) {
            emit Anomaly(msg.sender, "rate limit", WideAreaAugmentationSystemDefenseType.Monitoring);
            revert WAA__TooManyRequests();
        }
        // only authorized satellites/stations
        if (!isAuthorized(msg.sender)) revert WAA__NotAuthorized();

        Broadcast storage b = broadcasts[regionId];
        if (!b.voted[msg.sender]) {
            b.voted[msg.sender] = true;
            b.count++;
        }
        // commit when threshold reached
        if (b.count == threshold) {
            emit CorrectionCommit(regionId, data, WideAreaAugmentationSystemDefenseType.Redundancy);
        }
    }
}
