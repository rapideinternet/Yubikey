<?php

namespace Rapide\Yubikey\Contracts;

use Exception;

interface YubikeyService
{
    /**
     * Verify Yubico OTP against multiple URLs
     * Protocol specification 2.0 is used to construct validation requests.
     *
     * @param string $token         Yubico OTP
     * @param int    $use_timestamp 1=>send request with &timestamp=1 to
     *                              get timestamp and session information
     *                              in the response
     * @param bool   $wait_for_all  If true, wait until all
     *                              servers responds (for debugging)
     * @param string $sl            sync level in percentage between 0
     *                              and 100 or "fast" or "secure"
     * @param int    $timeout       Max number of seconds to wait
     *                              for responses
     *
     * @throws Exception
     *
     * @return mixed Exception on error, true otherwise
     */
    public function verify($token, $use_timestamp = null, $wait_for_all = false, $sl = null, $timeout = null): bool;

    /**
     * Specify to use a different URL part for verification.
     * The default is "api.yubico.com/wsapi/verify".
     *
     * @param string $url New server URL part to use
     */
    public function setURLpart($url): void;

    /**
     * Get URL part to use for validation.
     *
     * @return string Server URL part
     */
    public function getURLpart(): string;

    /**
     * Add another URLpart.
     *
     * @param $URLpart
     */
    public function addURLpart($URLpart): void;

    /**
     * Return the last query sent to the server, if any.
     *
     * @return string Request to server
     */
    public function getLastQuery(): string;

    /**
     * Return the last data received from the server, if any.
     *
     * @return string Output from server
     */
    public function getLastResponse(): string;

    /**
     * Get one parameter from last response.
     *
     * @param $parameter
     *
     * @return mixed Exception on error, string otherwise
     */
    public function getParameter($parameter);

    /**
     * Parse parameters from last response.
     *
     * @return array parameter array from last response
     */
    public function getParameters(): array;
}
