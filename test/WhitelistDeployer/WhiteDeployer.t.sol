// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../src/WhitelistDeployerV2/WhitelistDeployerV2.sol";
import "@oz/proxy/transparent/TransparentUpgradeableProxy.sol";
import "@oz/proxy/transparent/ProxyAdmin.sol";

contract WhitelistDeployerTest is Test {
    WhitelistDeployerV2 public implementation;
    TransparentUpgradeableProxy proxy;
    WhitelistDeployerV2 public whitelistDeployer;
    ProxyAdmin admin;
    address public sentry1;
    address public sentry2;
    address public deployer1;
    address public deployer2;
    address public admin_;

    function setUp() public {
        sentry1 = address(0x1);
        sentry2 = address(0x2);
        deployer1 = address(0x3);
        deployer2 = address(0x4);
        admin_ = address(0x5);
        admin = new ProxyAdmin();

        implementation = new WhitelistDeployerV2();
        proxy = new TransparentUpgradeableProxy(
            address(implementation),
            address(admin),
            ""
        );

        whitelistDeployer = WhitelistDeployerV2(address(proxy));
        address[] memory sentries = new address[](2);
        sentries[0] = sentry1;
        sentries[1] = sentry2;
        whitelistDeployer.initialize(admin_, sentries);
    }

    // create a test function for each function in the contract
    function testWhitelist() public {
        uint256 expiryTimestamp = block.timestamp + 1 days;

        // Only sentries should be able to whitelist
        vm.prank(admin_);
        whitelistDeployer.whitelist(deployer1, expiryTimestamp);
        assertEq(whitelistDeployer.isWhitelisted(deployer1), true);

        // Non-sentries should not be able to whitelist
        vm.prank(deployer1);
        vm.expectRevert(
            bytes(
                "AccessControl: account 0x0000000000000000000000000000000000000003 is missing role 0x5bea60102f2a7acc9e82b1af0e3bd4069661102bb5dd143a6051cd1980dded1c"
            )
        );
        whitelistDeployer.whitelist(deployer2, expiryTimestamp);
        assertEq(whitelistDeployer.isWhitelisted(deployer2), false);

        // Whitelist expiry time should be set correctly
        WhitelistDeployerV2.WhiteListInfo
            memory whitelistInfo = whitelistDeployer.getWhitelistInfo(
                deployer1
            );
        assertEq(whitelistInfo.expiryTimestamp, expiryTimestamp);

        // Whitelist should be deactivated after expiry time
        vm.warp(block.timestamp + 1 days);
        assertEq(whitelistDeployer.isWhitelisted(deployer1), false);
    }

    function testExpireWhitelist() public {
        uint256 expiryTimestamp = block.timestamp + 1 days;

        // Only sentries should be able to whitelist
        vm.prank(admin_);
        whitelistDeployer.whitelist(deployer1, expiryTimestamp);
        assertEq(whitelistDeployer.isWhitelisted(deployer1), true);

        vm.warp(block.timestamp + 1 days);
        assertEq(whitelistDeployer.isWhitelisted(deployer1), false);
        // when timestamp expire and whitelist is deactivated, it should be activated again
        WhitelistDeployerV2.WhiteListInfo
            memory whitelistInfo = whitelistDeployer.getWhitelistInfo(
                deployer1
            );
        assertEq(whitelistInfo.activated, true);
    }

    function testUnwhitelist() public {
        uint256 expiryTimestamp = block.timestamp + 1 days;

        // Whitelist deployer1
        vm.prank(admin_);
        whitelistDeployer.whitelist(deployer1, expiryTimestamp);
        assertEq(whitelistDeployer.isWhitelisted(deployer1), true);

        vm.prank(sentry1);
        // Only sentries should be able to unwhitelist
        whitelistDeployer.unwhitelist(deployer1);
        assertEq(whitelistDeployer.isWhitelisted(deployer1), false);

        // Non-sentries should not be able to unwhitelist
        vm.prank(deployer1);
        vm.expectRevert(
            bytes(
                "AccessControl: account 0x0000000000000000000000000000000000000003 is missing role 0x5bea60102f2a7acc9e82b1af0e3bd4069661102bb5dd143a6051cd1980dded1c"
            )
        );
        whitelistDeployer.unwhitelist(deployer2);
    }

    function testWhitelistAll() public {
        bool isWhitelistAll;

        // Only admin should be able to update whitelistAll flag
        vm.prank(admin_);
        whitelistDeployer.whitelistAll(true);
        isWhitelistAll = whitelistDeployer.isWhitelistAll();
        assertEq(isWhitelistAll, true);

        vm.prank(deployer1);
        vm.expectRevert(
            bytes(
                "AccessControl: account 0x0000000000000000000000000000000000000003 is missing role 0x0000000000000000000000000000000000000000000000000000000000000000"
            )
        );
        whitelistDeployer.whitelistAll(false);
        vm.prank(admin_);
        whitelistDeployer.whitelistAll(false);
        isWhitelistAll = whitelistDeployer.isWhitelistAll();
        assertEq(isWhitelistAll, false);
    }

    // fuzzing address to whitelist
    function testFuzzingWhitelist(address rand_adddress) public {
        uint256 expiryTimestamp = block.timestamp + 1 days;
        if (
            rand_adddress != admin_ &&
            rand_adddress != sentry1 &&
            rand_adddress != sentry2
        ) {
            vm.prank(rand_adddress);
            vm.expectRevert();
            whitelistDeployer.whitelist(deployer1, expiryTimestamp);
        }
    }

    // fuzzing address to unwhitelist
    function testFuzzingUnwhitelist(address rand_adddress) public {
        if (
            rand_adddress != admin_ &&
            rand_adddress != sentry1 &&
            rand_adddress != sentry2
        ) {
            vm.prank(rand_adddress);
            vm.expectRevert();
            whitelistDeployer.unwhitelist(deployer1);
        }
    }

    // fuzzing expiryTimestamp to whitelist
    function testFuzzingExpiryTimestamp(uint256 rand_expiryTimestamp) public {
        if (rand_expiryTimestamp > block.timestamp) {
            vm.prank(admin_);
            whitelistDeployer.whitelist(deployer1, rand_expiryTimestamp);
            vm.warp(rand_expiryTimestamp);
            assertEq(whitelistDeployer.isWhitelisted(deployer1), false);
        }
    }

    // when whitelistAll is true, why we can not be able to unwhitelist because of newcommer
    function testFuzzingWhitelistAll(bool rand_isWhitelistAll) public {
        vm.prank(admin_);
        whitelistDeployer.whitelistAll(rand_isWhitelistAll);

        if (rand_isWhitelistAll) {
            vm.prank(admin_);
            vm.expectRevert();
            whitelistDeployer.unwhitelist(deployer1);
        }
    }
}
