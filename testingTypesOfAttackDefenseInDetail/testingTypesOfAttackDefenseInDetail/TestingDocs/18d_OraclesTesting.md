📡 Oracle Testing in Smart Contracts
Oracle Testing ensures that your contract correctly integrates with off-chain data feeds (like Chainlink, Tellor, DIA, Pyth, etc.), and remains secure, fresh, and resilient to manipulation.

Smart contracts relying on oracles are vulnerable to price drift, update lags, stale data, or oracle spoofing — making oracle testing mission-critical for DeFi, NFT pricing, insurance, bridges, and prediction markets.

✅ Types of Oracle Testing
#	Type	Description
1	Freshness Testing	Ensures oracle data is updated recently (updatedAt, roundId).
2	Value Drift Testing	Compare on-chain price vs. expected range or TWAP to detect anomalies.
3	Fallback Oracle Testing	Simulate failure of primary oracle, validate fallback behavior.
4	Multi-Oracle Consensus Testing	Compare values from multiple sources (e.g., Chainlink vs Tellor).
5	Mock Oracle Testing	Use mock contracts to simulate oracle manipulation or edge values.
6	Stale Price Rejection	Ensure stale data (updatedAt + gracePeriod) is rejected.
7	Cross-Chain Oracle Testing	Validate consistency of price feeds across chains (e.g., L1 vs L2).
8	Oracle Downtime Simulation	Disable oracle updates, validate contract reaction.
9	Oracle Spoof Prevention	Validate only trusted oracles or adapters can provide data.
10	Rate-Limiting Oracle Use	Test that oracle calls are throttled to avoid DoS/gas spikes.

⚔️ Oracle Attack Types Caught by Testing
#	Attack Type	Description
1	Stale Oracle Exploit	Use outdated price to manipulate collateral, liquidation, or payout.
2	Oracle Drift Arbitrage	Bridge or trade based on mismatched price across chains.
3	Oracle Replacement Attack	Upgrade or switch oracle feed to malicious address.
4	Flash Oracle Manipulation	Temporarily distort price before update.
5	Cross-Chain Oracle Lag	Time-based price lag exploited across L1 ↔ L2.
6	Reentrancy via Oracle Callback	Oracle triggers external logic before state is updated.
7	Fake Oracle Signature	Relayer submits data from unverified source (off-chain signer).
8	Misordered Round Exploit	Use older roundId with higher value than current.
9	Gas Bomb Feed Update	Push high gas-cost updates to cause griefing.
10	Fallback Oracle Exploit	Trigger fallback to under-tested oracle that can be manipulated.

🛡️ Oracle Defense Types
#	Defense Type	Description
1	Timestamp Bound Check	Require oracle data is recent (updatedAt > block.timestamp - X).
2	Trusted Aggregator Binding	Hardcode and verify trusted oracle addresses.
3	Round Sequencing Check	Only accept newer roundIds than the last accepted.
4	Min-Max Deviation Filter	Reject updates with abnormal percent deviation.
5	Fallback Oracle Validation	Ensure fallback oracles meet the same safety criteria.
6	Access Control for Feed Updates	Only whitelisted updaters (Tellor, UMA, Pyth) can submit prices.
7	Replay Protection	Use nonce or round sequencing to block replayed updates.
8	Multi-Source Aggregation	Blend feeds using TWAP, median, or weighted average.
9	Oracle Freeze Guard	Detect frozen feeds and halt sensitive logic.
10	Cross-Chain Feed Synchronizer	Enforce consistency of value and timing across deployments.