// SPDX-License-Identifier: MIT
pragma solidity ^0.8.9;

interface IWhitelistDeployerV2 {
    struct WhiteListInfo {
        uint256 expiryTimestamp;
        bool activated;
    }
    /// @dev Emitted when a deployer address is whitelisted.
    event DeployerWhitelisted(
        address indexed deployer,
        uint256 indexed expireTime
    );
    /// @dev Emitted when deployer is unwhitelied.
    event DeployerUnwhitelisted(address indexed whitelistee);
    /// @dev Emitted when the permission for whitelisting all has been updated.
    event WhitelistAllChanged(bool indexed status);

    /// @dev Error when expiration time is invalid (e.g. expiration time is smaller than now).
    error ErrInvalidExpirationTime();
    /// @dev Error when sentry attempts to whitelist a newcomer deployer address.
    error ErrSentryAttemptsToWhitelistNewComer();
    /// @dev Error when sentry attempts to whitelist an address that has been unwhitelisted by admin before.
    error ErrSentryAttemptsToWhitelistABlacklistUser();
    /// @dev Error when attempting to unwhitelist an address that hasn't been whitelisted before.
    error ErrUnwhitelistANewcomer();

    /**
     * @dev Whitelists a new deployer address.
     * @param deployer The address of deployer.
     * @param expiryTimestamp The experation time for deployment.
     *
     * Requirements:
     * - Expiry time must be valid.
     * - Sentry can whitelist the address that has been whitelisted at least once.
     * - Only admin can whitelist new address.
     * - Sentry can not whitelist user who has been unwhitelisted by admin before.
     *
     * Emits the {WhitelistInfoUpdated} event.
     */
    function whitelist(address deployer, uint256 expiryTimestamp) external;

    /**
     * @dev Unwhitelists a address.
     * @param whitelistee The address of whitelistee.
     *
     * Requirements:
     * - Revert when whitelistee is a stranger address (not have been whitelisted before).
     *
     * Emits the {WhitelistInfoUpdated} event.
     */
    function unwhitelist(address whitelistee) external;

    /**
     * @dev Whitelists all deployer addresses with the specified permission flag.
     * @param status The permission flag to assign to whitelisted addresses.
     *
     * Emits the {WhitelistAllChanged} event.
     */
    function whitelistAll(bool status) external;

    /**
     * @dev Verifies whether the address deployer is whitelisted or not.
     * @param deployer Address of deployer.
     */
    function isWhitelisted(address deployer) external view returns (bool);

    /**
     * @dev Checks if all address is whitelisted or not.
     */
    function isWhitelistAll() external view returns (bool);

    /**
     * @dev Returns all addresses that have been whitelisted.
     */
    function getAllWhitelistedAddresses()
        external
        view
        returns (address[] memory);
}
