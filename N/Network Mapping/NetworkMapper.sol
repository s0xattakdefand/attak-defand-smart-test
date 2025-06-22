// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IContractProbe {
    function probe(bytes4 selector) external view returns (bool);
}

contract NetworkMapper {
    struct Mapping {
        address target;
        bytes4 selector;
        bool isLive;
    }

    Mapping[] public mapLog;

    function map(address[] calldata contracts, bytes4[] calldata selectors) external {
        for (uint256 i = 0; i < contracts.length; i++) {
            (bool ok, ) = contracts[i].staticcall(abi.encodePacked(selectors[i]));
            mapLog.push(Mapping(contracts[i], selectors[i], ok));
        }
    }

    function getLog(uint256 index) external view returns (address, bytes4, bool) {
        Mapping memory m = mapLog[index];
        return (m.target, m.selector, m.isLive);
    }

    function totalMappings() external view returns (uint256) {
        return mapLog.length;
    }
}
