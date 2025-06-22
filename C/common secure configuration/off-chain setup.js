const key = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("upgradeDelay"));
const hash = ethers.utils.keccak256(ethers.utils.toUtf8Bytes("48h"));
await contract.registerConfig("upgradeDelay", hash);
