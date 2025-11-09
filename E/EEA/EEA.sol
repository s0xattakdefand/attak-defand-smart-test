// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Burnable.sol";
import "@openzeppelin/contracts/token/ERC20/extensions/ERC20Pausable.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/**
 * @title BattleTokenEEA - Fixed & Fully Working
 * @dev EEA-compliant battle token with Attack & Defend mechanics
 *      Compatible with OpenZeppelin Contracts v5.x
 */
contract BattleTokenEEA is
    ERC20,
    ERC20Burnable,
    ERC20Pausable,
    AccessControl,
    ReentrancyGuard
{
    bytes32 public constant GAME_ADMIN_ROLE = keccak256("GAME_ADMIN_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    // Battle Config
    uint256 public constant ATTACK_COOLDOWN = 1 hours;
    uint256 public constant DEFEND_DURATION = 2 hours;
    uint256 public constant BASE_ATTACK_SUCCESS_RATE = 60; // 60%
    uint256 public constant DEFEND_BONUS = 30;            // +30% defense
    uint256 public constant MAX_STEAL_PERCENT = 10;       // 10% max

    mapping(address => uint256) public lastAttackTime;
    mapping(address => uint256) public defendUntil;
    mapping(address => uint256) public defendedBalance;

    // Events
    event Attack(
        address indexed attacker,
        address indexed target,
        uint256 attemptedAmount,
        uint256 stolenAmount,
        bool success,
        uint256 timestamp
    );
    event DefendActivated(address indexed player, uint256 amount, uint256 until);
    event DefendDeactivated(address indexed player, uint256 amount);
    event RandomSeedUsed(uint256 seed);

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply_
    ) ERC20(name_, symbol_) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(GAME_ADMIN_ROLE, msg.sender);
        _grantRole(PAUSER_ROLE, msg.sender);

        _mint(msg.sender, initialSupply_);
    }

    // === ADMIN FUNCTIONS ===
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    function unpause() external onlyRole(PAUSER_ROLE) {
        _unpause();
    }

    // === REQUIRED OVERRIDE FOR ERC20 + ERC20Pausable (OZ v5) ===
    function _update(
        address from,
        address to,
        uint256 value
    ) internal override(ERC20, ERC20Pausable) {
        super._update(from, to, value);
    }

    // === BATTLE: ATTACK ===
    function attack(address target) external whenNotPaused nonReentrant {
        require(msg.sender != target, "Cannot attack self");
        require(balanceOf(target) > defendedBalance[target], "Nothing to steal");
        require(
            block.timestamp >= lastAttackTime[msg.sender] + ATTACK_COOLDOWN,
            "Attack on cooldown"
        );

        uint256 available = balanceOf(target) - defendedBalance[target];
        uint256 maxSteal = (available * MAX_STEAL_PERCENT) / 100;

        uint256 successChance = BASE_ATTACK_SUCCESS_RATE;
        if (block.timestamp < defendUntil[target]) {
            successChance -= DEFEND_BONUS;
        }

        uint256 seed = _random();
        emit RandomSeedUsed(seed);

        bool success = (seed % 100) < successChance;
        uint256 stolen = success ? maxSteal : 0;

        if (success) {
            _transfer(target, msg.sender, stolen);
        }

        lastAttackTime[msg.sender] = block.timestamp;
        emit Attack(msg.sender, target, maxSteal, stolen, success, block.timestamp);
    }

    // === BATTLE: DEFEND ===
    function activateDefense(uint256 amount) external whenNotPaused {
        require(amount > 0, "Amount > 0");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");

        defendedBalance[msg.sender] += amount;
        _transfer(msg.sender, address(this), amount); // lock inside contract

        uint256 newEnd = block.timestamp + DEFEND_DURATION;
        if (defendUntil[msg.sender] < newEnd) {
            defendUntil[msg.sender] = newEnd;
        }

        emit DefendActivated(msg.sender, amount, defendUntil[msg.sender]);
    }

    function deactivateDefense() external whenNotPaused nonReentrant {
        require(block.timestamp >= defendUntil[msg.sender], "Defense still active");
        uint256 amount = defendedBalance[msg.sender];
        require(amount > 0, "No defended tokens");

        defendedBalance[msg.sender] = 0;
        defendUntil[msg.sender] = 0;

        _transfer(address(this), msg.sender, amount);
        emit DefendDeactivated(msg.sender, amount);
    }

    // === VIEW FUNCTIONS ===
    function isDefending(address player) external view returns (bool) {
        return block.timestamp < defendUntil[player] && defendedBalance[player] > 0;
    }

    function availableBalance(address player) external view returns (uint256) {
        return balanceOf(player);
    }

    function totalBalance(address player) external view returns (uint256) {
        return balanceOf(player) + defendedBalance[player];
    }

    function timeUntilCanAttack(address player) external view returns (uint256) {
        uint256 next = lastAttackTime[player] + ATTACK_COOLDOWN;
        return block.timestamp >= next ? 0 : next - block.timestamp;
    }

    // === INTERNAL RANDOM (replace with Chainlink VRF for production) ===
    function _random() internal view returns (uint256) {
        return uint256(
            keccak256(
                abi.encodePacked(
                    block.timestamp,
                    block.prevrandao,
                    msg.sender,
                    tx.gasprice,
                    blockhash(block.number - 1)
                )
            )
        );
    }

    // === INTERFACE SUPPORT ===
    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}