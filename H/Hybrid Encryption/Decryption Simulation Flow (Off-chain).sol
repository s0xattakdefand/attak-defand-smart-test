// Pseudo-JS (off-chain decrypt)
const aesKey = decryptRSA(privateKey, encryptedKey);
const plaintext = decryptAES(aesKey, encryptedData);
