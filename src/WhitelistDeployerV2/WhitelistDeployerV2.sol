// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

import "@oz/proxy/utils/Initializable.sol";
import "@oz/access/AccessControlEnumerable.sol";
import "@oz/utils/structs/EnumerableSet.sol";
import "./IWhitelistDeployerV2.sol";

contract WhitelistDeployerV2 is
    Initializable,
    AccessControlEnumerable,
    IWhitelistDeployerV2
{
    using EnumerableSet for EnumerableSet.AddressSet;
    /// @dev Equal to keccak256("SENTRY_ROLE").
    bytes32 public constant SENTRY_ROLE =
        0x5bea60102f2a7acc9e82b1af0e3bd4069661102bb5dd143a6051cd1980dded1c;

    /// @dev Gap for upgradability.
    uint256[50] private ____gap;
    /// @dev Mapping stores expiryTime per whitelisted address.
    mapping(address => WhiteListInfo) private _whitelisted;
    /// @dev Array stores all whitelisted addresses.
    EnumerableSet.AddressSet private _allWhitelistedAddresses;
    /// @dev Array stores list of addresses that have been unwhitelisted by admin.
    EnumerableSet.AddressSet private _unwhitelistedByAdmin;
    /// @dev Flag indicates whether whitelist all or not.
    bool private _isWhitelistAll;

    constructor() {
        _disableInitializers();
    }

    function initialize(
        address admin,
        address[] memory sentries
    ) public initializer {
        _setupRole(DEFAULT_ADMIN_ROLE, admin);
        _setupRole(SENTRY_ROLE, admin);
        uint256 sentriesLength = sentries.length;
        for (uint256 i; i < sentriesLength; ) {
            _setupRole(SENTRY_ROLE, sentries[i]);
            unchecked {
                ++i;
            }
        }
    }

    /// @dev See {IWhitelistDeployerV2-whitelist}.
    function whitelist(
        address deployer,
        uint256 expiryTimestamp
    ) external onlyRole(SENTRY_ROLE) {
        if (expiryTimestamp < block.timestamp)
            revert ErrInvalidExpirationTime();
        bool isAdmin = hasRole(DEFAULT_ADMIN_ROLE, msg.sender);
        if (!isAdmin && !_haveBeenWhitelistedBefore(deployer)) {
            revert ErrSentryAttemptsToWhitelistNewComer();
        }
        if (!isAdmin && _unwhitelistedByAdmin.contains(deployer)) {
            revert ErrSentryAttemptsToWhitelistABlacklistUser();
        }
        if (isAdmin) {
            _unwhitelistedByAdmin.remove(deployer);
        }
        _whitelisted[deployer] = WhiteListInfo(expiryTimestamp, true);
        if (!_allWhitelistedAddresses.contains(deployer)) {
            _allWhitelistedAddresses.add(deployer);
        }
        emit DeployerWhitelisted(deployer, expiryTimestamp);
    }

    /// @dev See {IWhitelistDeployerV2-unwhitelist}.
    function unwhitelist(address whitelistee) external onlyRole(SENTRY_ROLE) {
        if (!_haveBeenWhitelistedBefore(whitelistee))
            revert ErrUnwhitelistANewcomer();

        if (hasRole(DEFAULT_ADMIN_ROLE, msg.sender)) {
            _unwhitelistedByAdmin.add(whitelistee);
        }
        _whitelisted[whitelistee].activated = false;
        _allWhitelistedAddresses.remove(whitelistee);
        emit DeployerUnwhitelisted(whitelistee);
    }

    /// @dev See {IWhitelistDeployerV2-whitelistAll}.
    function whitelistAll(bool status) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _isWhitelistAll = status;
        emit WhitelistAllChanged(status);
    }

    /// @dev See {IWhitelistDeployerV2-isWhitelisted}.
    function isWhitelisted(address deployer) external view returns (bool) {
        WhiteListInfo memory whiteListInfo = _whitelisted[deployer];
        return
            _isWhitelistAll ||
            (whiteListInfo.activated &&
                block.timestamp < whiteListInfo.expiryTimestamp);
    }

    /// @dev See {IWhitelistDeployerV2-isWhitelistAll}.
    function isWhitelistAll() external view returns (bool) {
        return _isWhitelistAll;
    }

    /// @dev See {IWhitelistDeployerV2-getAllWhitelistedAddresses}.
    function getAllWhitelistedAddresses()
        external
        view
        returns (address[] memory)
    {
        return _allWhitelistedAddresses.values();
    }

    /// @dev See {IWhitelistDeployerV2-getWhitelistInfo}.
    function getWhitelistInfo(
        address deployer
    ) external view returns (WhiteListInfo memory) {
        return _whitelisted[deployer];
    }

    /**
     * @dev Returns true if user has been whitelisted before.
     * @param user Address of user.
     */
    function _haveBeenWhitelistedBefore(
        address user
    ) private view returns (bool) {
        return _whitelisted[user].expiryTimestamp > 0;
    }
}
