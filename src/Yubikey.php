<?php
/*
* This file is based on Monarobase-Yubikey (Laravel 4).
* And was modified for compatibility with newer versions.
*
* (c) 2015 Christian Hermann
* (c) 2013 Monarobase
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*
* @author    Lucas van der Have
* @author    Monarobase
* @author    Christian Hermann
* @package     Yubikey
* @copyright   (c) 2013 Monarobase <jonathan@monarobase.net>
*              (c) 2015 Chistian Hermann <c.hermann@bitbeans.de>
* @link        http://monarobase.net
* @link        https://github.com/bitbeans
*/

namespace Rapide\Yubikey;

use Config;

/**
 * Class Yubikey
 * @package Rapide\Yubikey
 */
class Yubikey implements YubikeyService
{

    /**
     * Yubico client ID
     * @var string
     */
    protected $_id;

    /**
     * Yubico client key
     * @var string
     */
    protected $_key;

    /**
     * URL part of validation server
     * @var string
     */
    protected $_url;

    /**
     * List with URL part of validation servers
     * @var array
     */
    protected $_url_list;

    /**
     * index to _url_list
     * @var int
     */
    protected $_url_index;

    /**
     * Last query to server
     * @var string
     */
    protected $_lastquery;

    /**
     * Response from server
     * @var string
     */
    protected $_response;

    /**
     * Flag whether to use https or not.
     * @var boolean
     */
    protected $_https = true;

    /**
     * Flag whether to verify HTTPS server certificates or not.
     * @var boolean
     */
    protected $_verify_https = true;

    /**
     * @var string
     */
    protected $_user_agent = '';

    /**
     * Constructor
     *
     * Sets up the object
     * @param array $config The client configuration
     * @access public
     * @throws \Exception
     */
    public function __construct(array $config = [])
    {
        $this->_id = $config['id'] ?? null;
        $this->_key = base64_decode($config['key'] ?? '');
        $this->_https = $config['https'] ?? true;
        $this->_verify_https = $config['verify_https'] ?? true;
        $this->_url_list = $config['url_list'] ?? [];
        $this->_user_agent = $config['user_agent'] ?? [];

        if (!$this->_id) {
            throw new \Exception('Check your CLIENT_ID');
        }
        if (!$this->_key) {
            throw new \Exception('Check your SECRET_KEY');
        }
        if ($this->_https) {
            $this->sslSupportAvailable();
        }
    }

    /**
     * Test if Curl support SSL
     * Will throw exception if curl was not complied with SSL support
     */
    protected function sslSupportAvailable()
    {
        if (!($version = curl_version()) || !($version['features'] & CURL_VERSION_SSL)) {
            throw new \Exception('HTTPS requested while Curl not compiled with SSL');
        }
    }

    /**
     * Specify to use a different URL part for verification.
     * The default is "api.yubico.com/wsapi/verify".
     *
     * @param string $url New server URL part to use
     * @access public
     */
    public function setURLpart($url): void
    {
        $this->_url = $url;
    }

    /**
     * Get URL part to use for validation.
     *
     * @return string  Server URL part
     * @access public
     */
    public function getURLpart(): string
    {
        return ($this->_url) ? $this->_url : "api.yubico.com/wsapi/verify";
    }

    /**
     * Add another URLpart.
     *
     * @access public
     * @param $URLpart
     */
    public function addURLpart($URLpart): void
    {
        $this->_url_list[] = $URLpart;
    }

    /**
     * Return the last query sent to the server, if any.
     *
     * @return string  Request to server
     * @access public
     */
    public function getLastQuery(): string
    {
        return $this->_lastquery;
    }

    /**
     * Return the last data received from the server, if any.
     *
     * @return string  Output from server
     * @access public
     */
    public function getLastResponse(): string
    {
        return $this->_response;
    }

    /**
     * Get one parameter from last response
     *
     * @param $parameter
     * @return mixed  Exception on error, string otherwise
     * @throws \Exception
     * @access public
     */
    public function getParameter($parameter)
    {
        $param_array = $this->getParameters();

        if (!empty($param_array) && array_key_exists($parameter, $param_array)) {
            return $param_array[$parameter];
        } else {
            throw new \Exception('UNKNOWN_PARAMETER');
        }
    }

    /**
     * Parse parameters from last response
     *
     * @return array  parameter array from last response
     * @access public
     */
    public function getParameters(): array
    {
        $params = explode("\n", trim($this->_response));

        foreach ($params as $param) {
            list($key, $val) = explode('=', $param, 2);
            $param_array[$key] = $val;
        }

        $param_array['identity'] = substr($param_array['otp'], 0, 12);

        return $param_array;
    }

    /**
     * Verify Yubico OTP against multiple URLs
     * Protocol specification 2.0 is used to construct validation requests
     *
     * @param string $token Yubico OTP
     * @param int $use_timestamp 1=>send request with &timestamp=1 to
     *                             get timestamp and session information
     *                             in the response
     * @param boolean $wait_for_all If true, wait until all
     *                               servers responds (for debugging)
     * @param string $sl Sync level in percentage between 0
     *                             and 100 or "fast" or "secure".
     * @param int $timeout Max number of seconds to wait
     *                             for responses
     * @return mixed               Exception on error, true otherwise
     * @access public
     * @throws \Exception
     */
    public function verify($token, $use_timestamp = null, $wait_for_all = false, $sl = null, $timeout = null): bool
    {
        /* Construct parameters string */
        $ret = $this->parsePasswordOTP($token);

        if (!$ret) {
            throw new \Exception('Could not parse Yubikey OTP');
        }

        $params = array('id' => $this->_id, 'otp' => $ret['otp'], 'nonce' => bin2hex(self::getRandomBytes(16)));

        /* Take care of protocol version 2 parameters */
        if ($use_timestamp) {
            $params['timestamp'] = 1;
        }
        if ($sl) {
            $params['sl'] = $sl;
        }
        if ($timeout) {
            $params['timeout'] = $timeout;
        }

        ksort($params);

        $parameters = '';
        foreach ($params as $p => $v) {
            $parameters .= "&" . $p . "=" . $v;
        }

        $parameters = ltrim($parameters, "&");

        /* Generate signature. */
        if ($this->_key <> "") {
            $signature = base64_encode(hash_hmac('sha1', $parameters, $this->_key, true));
            $signature = preg_replace('/\+/', '%2B', $signature);
            $parameters .= '&h=' . $signature;
        }

        /* Generate and prepare request. */
        $this->_lastquery = null;
        $this->URLreset();
        $mh = curl_multi_init();
        $ch = array();

        while ($URLpart = $this->getNextURLpart()) {
            /* Support https. */
            $query = ($this->_https) ? "https://" : "http://";
            $query .= $URLpart . "?" . $parameters;
            if ($this->_lastquery) {
                $this->_lastquery .= " ";
            }
            $this->_lastquery .= $query;

            $handle = curl_init($query);
            curl_setopt($handle, CURLOPT_USERAGENT, $this->_user_agent);
            curl_setopt($handle, CURLOPT_RETURNTRANSFER, 1);
            if (!$this->_verify_https) {
                curl_setopt($handle, CURLOPT_SSL_VERIFYPEER, 0);
            }
            curl_setopt($handle, CURLOPT_FAILONERROR, true);

            /*
             * If timeout is set, we better apply it here as well
             * in case the validation server fails to follow it.
             * */
            if ($timeout) {
                curl_setopt($handle, CURLOPT_TIMEOUT, $timeout);
            }
            curl_multi_add_handle($mh, $handle);
            $ch[(int)$handle] = $handle;
        }

        /* Execute and read request. */
        $this->_response = null;
        $replay = false;
        $valid = false;

        do {
            /* Let curl do its work. */
            while (($mrc = curl_multi_exec($mh, $active)) == CURLM_CALL_MULTI_PERFORM) {
                ;
            }
            while ($info = curl_multi_info_read($mh)) {
                if ($info['result'] == CURLE_OK) {

                    /* We have a complete response from one server. */

                    $str = curl_multi_getcontent($info['handle']);
                    $cinfo = curl_getinfo($info['handle']);

                    if ($wait_for_all) { # Better debug info
                        $this->_response .= 'URL=' . $cinfo['url'] . "\n" . $str . "\n";
                    }

                    if (preg_match("/status=([a-zA-Z0-9_]+)/", $str, $out)) {
                        $status = $out[1];

                        /*
                         * There are 3 cases.
                         *
                         * 1. OTP or Nonce values doesn't match - ignore
                         * response.
                         *
                         * 2. We have a HMAC key.  If signature is invalid -
                         * ignore response.  Return if status=OK or
                         * status=REPLAYED_OTP.
                         *
                         * 3. Return if status=OK or status=REPLAYED_OTP.
                         */
                        if (!preg_match("/otp=" . $params['otp'] . "/",
                                $str) || !preg_match("/nonce=" . $params['nonce'] . "/", $str)) {
                            /* Case 1. Ignore response. */
                        } elseif ($this->_key <> "") {
                            /* Case 2. Verify signature first */
                            $rows = explode("\r\n", trim($str));
                            $response = array();
                            foreach ($rows as $val) {
                                /* = is also used in BASE64 encoding so we only replace the first = by # which is not used in BASE64 */
                                $val = preg_replace('/=/', '#', $val, 1);
                                $row = explode("#", $val);
                                $response[$row[0]] = $row[1];
                            }

                            $parameters = [
                                'nonce',
                                'otp',
                                'sessioncounter',
                                'sessionuse',
                                'sl',
                                'status',
                                't',
                                'timeout',
                                'timestamp'
                            ];
                            sort($parameters);
                            $check = null;

                            foreach ($parameters as $param) {
                                if (array_key_exists($param, $response)) {
                                    if ($check) {
                                        $check = $check . '&';
                                    }
                                    $check = $check . $param . '=' . $response[$param];
                                }
                            }

                            $checksignature = base64_encode(hash_hmac('sha1', utf8_encode($check), $this->_key, true));

                            if (self::hashEquals($response['h'], $checksignature)) {
                                if ($status == 'REPLAYED_OTP') {
                                    if (!$wait_for_all) {
                                        $this->_response = $str;
                                    }
                                    $replay = true;
                                }

                                if ($status == 'OK') {
                                    if (!$wait_for_all) {
                                        $this->_response = $str;
                                    }
                                    $valid = true;
                                }
                            }
                        } else {
                            /* Case 3. We check the status directly */
                            if ($status == 'REPLAYED_OTP') {
                                if (!$wait_for_all) {
                                    $this->_response = $str;
                                }
                                $replay = true;
                            }

                            if ($status == 'OK') {
                                if (!$wait_for_all) {
                                    $this->_response = $str;
                                }
                                $valid = true;
                            }
                        }
                    }

                    if (!$wait_for_all && ($valid || $replay)) {
                        /* We have status=OK or status=REPLAYED_OTP, return. */
                        foreach ($ch as $h) {
                            curl_multi_remove_handle($mh, $h);
                            curl_close($h);
                        }

                        curl_multi_close($mh);

                        if ($replay) {
                            throw new \Exception('REPLAYED_OTP');
                        }
                        if ($valid) {
                            return true;
                        }

                        throw new \Exception($status);
                    }

                    curl_multi_remove_handle($mh, $info['handle']);
                    curl_close($info['handle']);
                    unset($ch[(int)$info['handle']]);
                }
                curl_multi_select($mh);
            }
        } while ($active);

        /* Typically this is only reached for wait_for_all=true or
         * when the timeout is reached and there is no
         * OK/REPLAYED_REQUEST answer (think firewall).
         */

        foreach ($ch as $h) {
            curl_multi_remove_handle($mh, $h);
            curl_close($h);
        }

        curl_multi_close($mh);

        if ($replay) {
            throw new \Exception('REPLAYED_OTP');
        }
        if ($valid) {
            return true;
        }

        throw new \Exception('NO_VALID_ANSWER');
    }

    /**
     * Parse input string into password, yubikey prefix,
     * ciphertext, and OTP.
     *
     * @param $str
     * @param string $delim
     * @return bool Keyed array with fields
     * @access public
     */
    protected function parsePasswordOTP($str, $delim = '[:]'): bool
    {
        if (!preg_match("/^((.*)" . $delim . ")?(([cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{0,16})([cbdefghijklnrtuvCBDEFGHIJKLNRTUV]{32}))$/",
            $str, $matches)) {
            /* Dvorak? */
            if (!preg_match("/^((.*)" . $delim . ")?(([jxe.uidchtnbpygkJXE.UIDCHTNBPYGK]{0,16})([jxe.uidchtnbpygkJXE.UIDCHTNBPYGK]{32}))$/",
                $str, $matches)) {
                return false;
            } else {
                $ret['otp'] = strtr($matches[3], "jxe.uidchtnbpygk", "cbdefghijklnrtuv");
            }
        } else {
            $ret['otp'] = $matches[3];
        }

        $ret['password'] = $matches[2];
        $ret['prefix'] = $matches[4];
        $ret['ciphertext'] = $matches[5];

        return $ret;
    }

    /**
     * Get a string of cryptographically secure pseudorandom bytes
     *
     * @param int $num
     * @return string
     * @throws \Exception
     */
    protected static function getRandomBytes($num = 16): string
    {
        static $which = null;
        if ($which === null) {
            if (\function_exists('\\random_bytes') && \version_compare(\phpversion(), '7.0.0', '>=')) {
                $which = 'php7';
            } elseif (\function_exists('\\openssl_random_pseudo_bytes')) {
                $which = 'openssl';
            } elseif (\function_exists('\\mcrypt_create_iv')) {
                $which = 'mcrypt';
            } elseif (\is_readable('/dev/urandom')) {
                $which = 'urandom';
            } else {
                $which = 'fallback';
            }
        }

        if ($num < 1 || $num > PHP_INT_MAX) {
            return false;
        }

        // Now let's get some random bytes
        switch ($which) {
            case 'php7':
                return \random_bytes($num);
            case 'mcrypt':
                return \mcrypt_create_iv($num, MCRYPT_DEV_URANDOM);
            case 'openssl';
                return \openssl_random_pseudo_bytes($num);
            case 'urandom':
                $fp = \fopen('/dev/urandom', 'rb');
                \stream_set_read_buffer($fp, 0);
                $bytes = \fread($fp, $num);
                \fclose($fp);
                return $bytes;
            default:
                // I really hope this is never necessary
                $bytes = '';
                for ($i = 0; $i < $num; ++$i) {
                    $bytes .= \chr(\mt_rand(0, 255) ^ \rand(0, 255));
                }

                $xorbuf = \sha1(\json_encode($_SERVER), true);
                while (self::safeStrlen($xorbuf) < $num) {
                    $xorbuf .= \sha1(
                        \uniqid(
                            \md5(
                                \microtime(true) . \lcg_value()
                            ),
                            true
                        ),
                        true
                    );
                }
                for ($i = 0; $i < $num; ++$i) {
                    $bytes[$i] ^= $xorbuf[$i];
                }

                return $bytes;
        }
    }

    /**
     * Get the length of a string, irrespective to mbstring.func_overload
     *
     * @param string $string
     * @return int
     */
    protected static function safeStrlen($string): int
    {
        // Optimization -- only search once:
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('mb_strlen');
        }
        if ($exists) {
            return \mb_strlen($string, '8bit');
        }
        return \strlen($string);
    }

    /**
     * Resets index to URL list
     *
     * @access public
     */
    protected function URLreset(): void
    {
        $this->_url_index = 0;
    }

    /**
     * Get next URL part from list to use for validation.
     *
     * @return mixed string with URL part of false if no more URLs in list
     * @throws \Exception
     * @access public
     */
    protected function getNextURLpart()
    {
        if (count($this->_url_list) === 0) {
            throw new \Exception('No api endpoints provided');
        }

        $url_list = $this->_url_list;
        return ($this->_url_index >= count($url_list)) ? false : $url_list[$this->_url_index++];
    }

    /**
     * Compare two hashes in constant time
     *
     * @param string $knownString
     * @param string $userString
     * @return boolean
     */
    protected static function hashEquals($knownString, $userString): bool
    {
        static $exists = null;
        if ($exists === null) {
            $exists = \function_exists('\\hash_equals');
        }
        if ($exists) {
            return \hash_equals($knownString, $userString);
        }
        $length = self::safeStrlen($knownString);
        if ($length !== self::safeStrlen($userString)) {
            return false;
        }
        $r = 0;
        for ($i = 0; $i < $length; ++$i) {
            $r |= \ord($userString[$i]) ^ \ord($knownString[$i]);
        }
        return $r === 0;
    }

}
