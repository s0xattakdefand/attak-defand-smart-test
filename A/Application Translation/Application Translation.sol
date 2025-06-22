// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

interface ITargetApp {
    function execute(bytes calldata payload) external returns (bool);
}

contract ApplicationTranslator {
    mapping(bytes4 => bytes4) public selectorMap;
    mapping(bytes32 => bool) public usedTranslations;

    address public trustedSource;
    ITargetApp public target;

    event TranslationExecuted(address indexed caller, bytes4 originalSelector, bytes4 translatedSelector);
    event TranslationBlocked(address indexed caller, string reason);

    constructor(address _source, address _target) {
        trustedSource = _source;
        target = ITargetApp(_target);
    }

    modifier onlyTrusted() {
        require(msg.sender == trustedSource, "Not trusted source");
        _;
    }

    function registerTranslation(bytes4 fromSel, bytes4 toSel) external onlyTrusted {
        selectorMap[fromSel] = toSel;
    }

    function translateAndForward(bytes calldata input, bytes32 uniqueId) external onlyTrusted returns (bool) {
        require(!usedTranslations[uniqueId], "Replay detected");
        usedTranslations[uniqueId] = true;

        bytes4 fromSelector;
        assembly {
            fromSelector := calldataload(input.offset)
        }

        bytes4 toSelector = selectorMap[fromSelector];
        if (toSelector == bytes4(0)) {
            emit TranslationBlocked(msg.sender, "Selector not registered");
            revert("Translation not found");
        }

        bytes memory translated = abi.encodePacked(toSelector, input[4:]);
        emit TranslationExecuted(msg.sender, fromSelector, toSelector);
        return target.execute(translated);
    }
}
