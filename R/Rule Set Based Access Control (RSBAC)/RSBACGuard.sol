// SPDX-License-Identifier: MIT
pragma solidity ^0.8.21;

interface IEntropyScorer {
    function selectorEntropy(bytes4 sel) external view returns (uint8);
}

contract RSBACGuard {
    struct Rule {
        bool enabled;
        bytes4 selector;
        address subject;
        uint8 maxEntropy;
        uint256 startBlock;
        uint256 endBlock;
    }

    Rule[] public rules;
    IEntropyScorer public scorer;

    event AccessDenied(address indexed sender, bytes4 selector, string reason);
    event RuleMatched(uint indexed ruleId, address indexed sender, bytes4 selector);

    constructor(address entropyOracle) {
        scorer = IEntropyScorer(entropyOracle);
    }

    function addRule(
        bytes4 selector,
        address subject,
        uint8 maxEntropy,
        uint256 startBlock,
        uint256 endBlock
    ) external {
        rules.push(Rule(true, selector, subject, maxEntropy, startBlock, endBlock));
    }

    modifier onlyAllowed() {
        bytes4 sel = msg.sig;
        bool passed;
        for (uint i = 0; i < rules.length; i++) {
            Rule memory r = rules[i];
            if (
                r.enabled &&
                r.selector == sel &&
                r.subject == msg.sender &&
                scorer.selectorEntropy(sel) <= r.maxEntropy &&
                block.number >= r.startBlock &&
                block.number <= r.endBlock
            ) {
                emit RuleMatched(i, msg.sender, sel);
                passed = true;
                break;
            }
        }

        if (!passed) {
            emit AccessDenied(msg.sender, sel, "RSBAC: rule denied");
            revert("RSBAC: rule denied");
        }
        _;
    }
}
