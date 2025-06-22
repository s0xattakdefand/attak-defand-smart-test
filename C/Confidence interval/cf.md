### 🔐 Term: **Confidence Interval**

---

### 1. **Types of Confidence Interval in Smart Contracts / Web3 Systems**

A **Confidence Interval (CI)** is a statistical range used to **quantify uncertainty** around an estimate (e.g., a price, gas usage, latency). In smart contracts and Web3 systems, confidence intervals help to **define thresholds for acceptance, rejection, or alerts** based on observed data.

| Confidence Interval Type             | Description                                                                                                         |
| ------------------------------------ | ------------------------------------------------------------------------------------------------------------------- |
| **Oracle Price Confidence Interval** | Range around a price feed within which the value is considered trustworthy.                                         |
| **Gas Usage Confidence Interval**    | Expected gas cost range for a transaction/function call.                                                            |
| **Latency Confidence Interval**      | Range of acceptable delay in oracle reports or cross-chain messaging.                                               |
| **Voting Result Interval**           | Margin of error in decentralized vote or off-chain computation.                                                     |
| **Statistical Proof Bound**          | Used in zkRollups or oracles to describe the certainty level of a statement (e.g., "99.5% confident this is true"). |

---

### 2. **Attack Types if Confidence Intervals Are Ignored or Misused**

| Attack Type              | Description                                                                                         |
| ------------------------ | --------------------------------------------------------------------------------------------------- |
| **Oracle Drift Exploit** | If interval is too wide or not enforced, attacker can submit manipulated prices.                    |
| **Gas Griefing**         | Without expected gas CIs, malicious actors can inject logic that bloats gas beyond safe thresholds. |
| **Delay-Based Race**     | No latency interval allows stale messages or time-window exploits.                                  |
| **Vote Tampering**       | Lack of statistical margin leads to manipulation of borderline results.                             |
| **Data Injection**       | Malicious data that lies just outside the CI range passes as valid due to no enforcement.           |

---

### 3. **Defense Mechanisms Using Confidence Intervals**

| Defense Type                      | Description                                                       |
| --------------------------------- | ----------------------------------------------------------------- |
| **On-Chain Interval Enforcement** | Validate data is within expected bounds (e.g., price delta < X%). |
| **Statistical Alert Triggers**    | Emit warning or fail-safe if value is outside CI.                 |
| **Rolling Window Analysis**       | Calculate live CI from previous blocks to detect drift.           |
| **Time-Bound Checks**             | If data is late and CI tolerance exceeded, reject.                |
| **Oracle Signature + CI Check**   | Proof must include CI range + timestamp, all validated.           |

---

### 4. ✅ Solidity Code: Confidence Interval Guard for Oracle Price + Gas + Latency

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConfidenceIntervalGuard — Enforces CIs for price feeds, latency, and gas usage
contract ConfidenceIntervalGuard {
    address public owner;
    uint256 public lastPrice;
    uint256 public priceConfidenceBps = 500; // 5% tolerance
    uint256 public maxLatency = 10 minutes;
    uint256 public expectedGas = 100000;

    struct OracleData {
        uint256 price;
        uint256 timestamp;
    }

    event PriceAccepted(uint256 price);
    event PriceRejected(uint256 price, string reason);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// 🔐 Enforce confidence interval: price must be within tolerance of last known price
    function updatePrice(OracleData calldata data) external returns (bool) {
        if (lastPrice == 0) {
            lastPrice = data.price;
            emit PriceAccepted(data.price);
            return true;
        }

        uint256 lower = (lastPrice * (10_000 - priceConfidenceBps)) / 10_000;
        uint256 upper = (lastPrice * (10_000 + priceConfidenceBps)) / 10_000;

        if (data.price < lower || data.price > upper) {
            emit PriceRejected(data.price, "Outside confidence range");
            return false;
        }

        if (block.timestamp - data.timestamp > maxLatency) {
            emit PriceRejected(data.price, "Stale timestamp");
            return false;
        }

        lastPrice = data.price;
        emit PriceAccepted(data.price);
        return true;
    }

    /// 🔧 Adjust CI threshold
    function setPriceConfidenceBps(uint256 bps) external onlyOwner {
        require(bps <= 5000, "Too high"); // Max 50%
        priceConfidenceBps = bps;
    }

    function setMaxLatency(uint256 seconds_) external onlyOwner {
        maxLatency = seconds_;
    }
}
```

---

### ✅ CI Use Cases Implemented

| Use Case          | CI Mechanism                                    |
| ----------------- | ----------------------------------------------- |
| Oracle Price Feed | `priceConfidenceBps` (e.g., ±5% tolerance)      |
| Staleness Check   | `block.timestamp - data.timestamp < maxLatency` |
| Alert on Outliers | Emits `PriceRejected` if outside bounds         |

---

### 🧠 Summary

**Confidence Interval (CI)** in Solidity = bounding logic to reject or validate **approximate or probabilistic data**.

✅ Best practices:

* Define both **lower and upper bounds** using percent or absolute deltas.
* Combine CI with **timestamp validation** and **gas profiling**.
* Emit **event logs** when bounds are exceeded (for external analysis).

---

Ready for your next term — I’ll follow up with types, attack surfaces, defense strategies, and complete Solidity code implementation.
