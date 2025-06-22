// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title StrongStarSuite.sol
/// @notice On‑chain analogues of the Bell–LaPadula **Strong Star** property:
///           “No read up, no write down”
///
/// Four modules:
///   1) SimpleDataVuln           – no enforcement  
///   2) Attack_ReadUp            – low‑level reads high‑level  
///   3) Attack_WriteDown         – high‑level writes low‑level  
///   4) StrongStarSafe           – enforces same‑level read/write  

error SS__NotAllowed();

////////////////////////////////////////////////////////////////////////
// 1) SIMPLE DATA STORE (VULNERABLE)
//    Type: multi‑level data store with no access checks
//    Attack: any subject may read or write any classification
////////////////////////////////////////////////////////////////////////
contract SimpleDataVuln {
    mapping(uint8 => bytes) public dataStore;

    /// set data at classification `cls`
    function setData(uint8 cls, bytes calldata data) external {
        dataStore[cls] = data;
    }

    /// get data at classification `cls`
    function getData(uint8 cls) external view returns (bytes memory) {
        return dataStore[cls];
    }
}

////////////////////////////////////////////////////////////////////////
// 2) ATTACK: READ‑UP VIOLATION
//    Type: low‑level subject reads high‑level data
////////////////////////////////////////////////////////////////////////
contract Attack_ReadUp {
    SimpleDataVuln public target;
    constructor(SimpleDataVuln _t) { target = _t; }

    /// attempt to read data at a higher classification than own
    function readHigh(uint8 highCls) external view returns (bytes memory) {
        return target.getData(highCls);
    }
}

////////////////////////////////////////////////////////////////////////
// 3) ATTACK: WRITE‑DOWN VIOLATION
//    Type: high‑level subject writes to a lower classification
////////////////////////////////////////////////////////////////////////
contract Attack_WriteDown {
    SimpleDataVuln public target;
    constructor(SimpleDataVuln _t) { target = _t; }

    /// attempt to write data at a lower classification than own
    function writeLow(uint8 lowCls, bytes calldata data) external {
        target.setData(lowCls, data);
    }
}

////////////////////////////////////////////////////////////////////////
// 4) STRONG‑STAR SAFE
//    Type: enforce “no read up, no write down” by allowing only same‑level access
////////////////////////////////////////////////////////////////////////
contract StrongStarSafe {
    mapping(address => uint8) public subjectLevel;
    mapping(uint8   => bytes) public dataStore;
    address public immutable owner;
    error SS__NotAllowed();

    event LevelSet(address indexed subject, uint8 level);
    event DataWritten(address indexed subject, uint8 cls);

    constructor() {
        owner = msg.sender;
    }

    /// only owner may assign clearance levels
    function setLevel(address subject, uint8 level) external {
        if (msg.sender != owner) revert SS__NotAllowed();
        subjectLevel[subject] = level;
        emit LevelSet(subject, level);
    }

    /// only a subject whose level equals `cls` may write
    function setData(uint8 cls, bytes calldata data) external {
        if (subjectLevel[msg.sender] != cls) revert SS__NotAllowed();
        dataStore[cls] = data;
        emit DataWritten(msg.sender, cls);
    }

    /// only a subject whose level equals `cls` may read
    function getData(uint8 cls) external view returns (bytes memory) {
        if (subjectLevel[msg.sender] != cls) revert SS__NotAllowed();
        return dataStore[cls];
    }
}
