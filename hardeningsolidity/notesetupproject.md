### create the folder name
mkdir hardeningsolidity
cd to this folder
run: forge init --force
run: forge test
run: forge build

## adding the dependencies
add forge-std for test utilities:
    - forge install foundry-rs/forge-std

## add slither for security analysis
    - npm install -g slither-analyzer

## create test if installed
    - create this test file:
        - touch test/Sanity.t.sol

    - paste this code
        ```bash
        // SPDX-License-Identifier: UNLICENSED
        pragma solidity ^0.8.13;

        import "forge-std/Test.sol";

        contract SanityCheck is Test {
            function testTrueIsTrue() public {
                assertTrue(true);
            }
        }

        ```
    ## require checks
        - run the test type:
            - forge build
            - forge test
    ## install the forge-std
        - forge install foundry-rs/forge-std

    ##  git config --global user.email "gainwealthx@gmail.com"
        git config --global user.name "Seng Keat"