<?php

namespace Bitrix24;

use Exception;
use Bitrix24\Contracts\iBitrix24;
use Bitrix24\Traits\{
    Webhook,
    Batch,
    Proxy,
    OAuth
};
use Bitrix24\Exceptions\{
    Bitrix24ApiException,
    Bitrix24BadJsonResponseException,
    Bitrix24BadGatewayException,
    Bitrix24EmptyResponseException,
    Bitrix24Exception,
    Bitrix24InsufficientScope,
    Bitrix24IoException,
    Bitrix24MethodNotFoundException,
    Bitrix24PaymentRequiredException,
    Bitrix24PortalDeletedException,
    Bitrix24PortalRenamedException,
    Bitrix24RestApiUnavailableOnFreeTariffException,
    Bitrix24SecurityException,
    Bitrix24TokenIsExpiredException,
    Bitrix24TokenIsInvalidException,
    Bitrix24WrongClientException
};
use Psr\Log\LoggerInterface;
use Psr\Log\NullLogger;

class Bitrix24 implements iBitrix24
{
    use Webhook, Batch, Proxy, OAuth;

    /**
     * @var string SDK version
     */
    const VERSION = '1.2.3';

    /**
     * @var array raw request, contain all cURL options array and API query
     */
    protected $rawRequest;

    /**
     * @var array, contain all api-method parameters, will be available after call method
     */
    protected $methodParameters;

    /**
     * @var array request info data structure from curl_getinfo function
     */
    protected $requestInfo;

    /**
     * @var bool if true raw response from bitrix24 will be available from method getRawResponse, this is debug mode
     */
    protected bool $isSaveRawResponse = false;

    /**
     * @var array raw response from bitrix24
     */
    protected $rawResponse;

    /**
     * @var array custom options for cURL
     */
    protected array $customCurlOptions;

    /**
     * @see https://github.com/Seldaek/monolog
     * @var \Monolog\Logger PSR-3 compatible logger, use only from wrappers methods log*
     */
    protected $log;

    /**
     * @var integer CURL request count retries
     */
    protected int $retriesToConnectCount;

    /**
     * @var integer retries to connect timeout in microseconds
     */
    protected int $retriesToConnectTimeout;

    /**
     * @var callable callback for expired tokens
     */
    protected $_onExpiredToken;

    /**
     * @var callable callback after api method called
     */
    protected $_onCallApiMethod;
    /**
     * @var callable callback after portal renamed
     */
    protected $_onPortalRenamed;

    /**
     * @var bool ssl verify for checking CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST
     */
    protected bool $sslVerify = false;

    /**
     * Create a object to work with Bitrix24 REST API service
     *
     * @param  bool  $isSaveRawResponse  - if true raw response from bitrix24 will be available from method getRawResponse, this is debug mode
     * @param  null|LoggerInterface  $obLogger  - instance of \Monolog\Logger
     *
     * @return Bitrix24
     * @throws Bitrix24Exception
     *
     */
    public function __construct(bool $isSaveRawResponse = false, LoggerInterface $obLogger = null)
    {
        $this->isSaveRawResponse = $isSaveRawResponse;
        $this->log = is_null($obLogger) ? new NullLogger() : clone $obLogger;
        $this->setRetriesToConnectCount(2);
        $this->setRetriesToConnectTimeout(1000000);
    }

    /**
     * Set function called on token expiration. Callback receives instance as first parameter.
     * If callback returns true, API call will be retried.
     *
     * @param  callable  $callback
     */
    public function setOnExpiredToken(callable $callback)
    {
        $this->_onExpiredToken = $callback;
    }

    /**
     * Set function called on portal renamed. Callback receives instance as first parameter and new portalUrl
     * If callback returns true, last API call will be retried
     *
     * @param  callable  $callback
     *
     * @return void
     */
    public function setOnPortalRenamed(callable $callback)
    {
        $this->_onPortalRenamed = $callback;
    }

    /**
     * Set function called after api method executed. Callback receives instance as first parameter, method name as second.
     *
     * @param  callable  $callback
     */
    public function setOnCallApiMethod(callable $callback)
    {
        $this->_onCallApiMethod = $callback;
    }

    /**
     * Set custom cURL options, overriding default ones
     *
     * @link http://php.net/manual/en/function.curl-setopt.php
     *
     * @param  array  $options  - array(CURLOPT_XXX => value1, CURLOPT_XXX2 => value2,...)
     *
     * @return self
     */
    public function setCustomCurlOptions(array $options): self
    {
        $this->customCurlOptions = $options;
        return $this;
    }

    /**
     * Return additional parameters of last api-call. Data available after you try to call method call
     *
     * @return array | null
     */
    public function getMethodParameters()
    {
        return $this->methodParameters;
    }

    /**
     * Disable of checking CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST
     */
    public function setDisabledSslVerify()
    {
        $this->sslVerify = false;
    }

    /**
     * Enable of checking CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST
     */
    public function setEnabledSslVerify()
    {
        $this->sslVerify = true;
    }

    /**
     * Execute a request API to Bitrix24 using cURL
     *
     * @param  string  $url
     * @param  array  $additionalParameters
     *
     * @return array
     * @throws Exception
     */
    protected function executeRequest($url, array $additionalParameters = [])
    {
        $retryableErrorCodes = [
            CURLE_COULDNT_RESOLVE_HOST,
            CURLE_COULDNT_CONNECT,
            CURLE_HTTP_NOT_FOUND,
            CURLE_READ_ERROR,
            CURLE_OPERATION_TIMEOUTED,
            CURLE_HTTP_POST_ERROR,
            CURLE_SSL_CONNECT_ERROR,
        ];

        $curlOptions = [
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_RETURNTRANSFER => true,
            CURLINFO_HEADER_OUT => true,
            CURLOPT_VERBOSE => $this->isSaveRawResponse,
            CURLOPT_CONNECTTIMEOUT => 9,
            CURLOPT_TIMEOUT => 55,
            CURLOPT_USERAGENT => strtolower(__CLASS__.'-PHP-SDK/v'.self::VERSION),
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => http_build_query($additionalParameters),
            CURLOPT_URL => $url,
        ];

        if (!$this->sslVerify) {
            $curlOptions[CURLOPT_SSL_VERIFYPEER] = 0;
            $curlOptions[CURLOPT_SSL_VERIFYHOST] = 0;
        }

        if ($this->getProxy()) {
            $curlOptions[CURLOPT_PROXY] = $this->getProxy();
        }

        /*
        if (strpos($url, 'bitrix24.kz') !== false) {
            $curlOptions[CURLOPT_RESOLVE] = ["{$this->getDomain()}:443:195.49.210.56"];
        }*/

        if (!empty($this->customCurlOptions)) {
            foreach ($this->customCurlOptions as $customCurlOptionKey => $customCurlOptionValue) {
                $curlOptions[$customCurlOptionKey] = $customCurlOptionValue;
            }
        }

        $this->rawRequest = $curlOptions;
        $curl = curl_init();
        curl_setopt_array($curl, $curlOptions);

        $curlResult = false;
        $retriesCnt = $this->retriesToConnectCount;
        while ($retriesCnt--) {
            $this->log->debug(sprintf('try [%s] to connect to host [%s]', $retriesCnt, $this->getDomain()));
            $curlResult = curl_exec($curl);
            // handling network I/O errors
            if (false === $curlResult) {
                $curlErrorNumber = curl_errno($curl);
                $errorMsg = sprintf(
                    '[%s] in try[%s] cURL error (code %s): %s'.PHP_EOL,
                    $this->getDomain(),
                    $retriesCnt,
                    $curlErrorNumber,
                    curl_error($curl)
                );
                if (false === in_array($curlErrorNumber, $retryableErrorCodes, true) || !$retriesCnt) {
                    $this->log->error($errorMsg, $this->getErrorContext());
                    curl_close($curl);
                    throw new Bitrix24IoException($errorMsg);
                } else {
                    $this->log->warning($errorMsg, $this->getErrorContext());
                }
                usleep($this->getRetriesToConnectTimeout());
                continue;
            }
            $this->requestInfo = curl_getinfo($curl);
            $this->rawResponse = $curlResult;
            $this->log->debug('cURL request info', [$this->getRequestInfo()]);
            curl_close($curl);
            break;
        }

        // handling URI level resource errors
        switch ($this->requestInfo['http_code']) {
            case 403:
                $errorMsg = sprintf('403 error! Maybe portal [%s] deleted, query aborted!', $this->getDomain());
                $this->log->error($errorMsg, $this->getErrorContext());
                throw new Bitrix24PortalDeletedException($errorMsg);
            case 302:
                $this->log->warning('bitrix24Portal.renamed', [
                    'oldDomainUrl' => $this->getDomain(),
                    'newDomainUrl' => $this->requestInfo['redirect_url'],
                ]);

                $newDomainHost = parse_url((string) $this->requestInfo['redirect_url'], PHP_URL_HOST);
                if (is_callable($this->_onPortalRenamed)) {
                    $this->log->debug('bitrix24Portal.renamed.callbackFound');
                    $isRetryApiCall = call_user_func($this->_onPortalRenamed, $this, $newDomainHost);
                    if ($isRetryApiCall) {
                        $newUrl = str_replace($this->getDomain(), $newDomainHost, $url);
                        $this->log->debug('bitrix24Portal.renamed.tryToRetryLastQueryByNewHost', [
                            'oldUrl' => $url,
                            'newUrl' => $url,
                        ]);

                        return $this->executeRequest($newUrl, $additionalParameters);
                    }
                } else {
                    throw new Bitrix24PortalRenamedException(
                        sprintf(
                            'bitrix24 portal %s renamed to %s',
                            $this->getDomain(),
                            $newDomainHost
                        )
                    );
                }

                break;
            case 502:
                $errorMsg = sprintf('bad gateway to portal [%s]', $this->getDomain());
                $this->log->error($errorMsg, $this->getErrorContext());
                throw new Bitrix24BadGatewayException($errorMsg);
        }

        // handling server-side API errors: empty response from bitrix24 portal
        if ($curlResult === '') {
            $errorMsg = sprintf('empty response from portal [%s]', $this->getDomain());
            $this->log->error($errorMsg, $this->getErrorContext());
            throw new Bitrix24EmptyResponseException($errorMsg);
        }

        // handling json_decode errors
        $jsonResult = json_decode($curlResult, true);
        unset($curlResult);
        $jsonErrorCode = json_last_error();
        if (null === $jsonResult && (JSON_ERROR_NONE !== $jsonErrorCode)) {
            $errorMsg = 'Fatal error in function json_decode.'.PHP_EOL.'Error code: '.$jsonErrorCode.PHP_EOL.'Error message: '.json_last_error_msg().PHP_EOL.'URL: '.$url;
            $this->log->error($errorMsg, $this->getErrorContext());

            // TODO: If more - use switch
            if ($jsonErrorCode === JSON_ERROR_SYNTAX) {
                throw new Bitrix24BadJsonResponseException($errorMsg);
            }

            throw new Bitrix24Exception($errorMsg);
        }

        return $jsonResult;
    }

    /**
     * get error context
     *
     * @return array
     */
    protected function getErrorContext()
    {
        return [
            // portal specific settings
            'B24_DOMAIN' => $this->getDomain(),
            'B24_MEMBER_ID' => $this->getMemberId(),
            'B24_ACCESS_TOKEN' => $this->getAccessToken(),
            'B24_REFRESH_TOKEN' => $this->getRefreshToken(),
            // application settings
            'APPLICATION_ID' => $this->getApplicationId(),
            'APPLICATION_SECRET' => $this->getApplicationSecret(),
            'REDIRECT_URI' => $this->getRedirectUri(),
            // network
            'RAW_REQUEST' => $this->getRawRequest(),
            'CURL_REQUEST_INFO' => $this->getRequestInfo(),
            'RAW_RESPONSE' => $this->getRawResponse(),
        ];
    }

    /**
     * Return raw request, contain all cURL options array and API query. Data available after you try to call method call
     * numbers of array keys is const of cURL module. Example: CURLOPT_RETURNTRANSFER = 19913
     *
     * @return array | null
     */
    public function getRawRequest(): ?array
    {
        return $this->rawRequest ?? null;
    }

    /**
     * Return result from function curl_getinfo. Data available after you try to call method call
     *
     * @return array | null
     */
    public function getRequestInfo(): ?array
    {
        return $this->requestInfo ?? null;
    }

    /**
     * Get raw response from Bitrix24 before json_decode call, method available only in debug mode.
     * To activate debug mode you must before set to true flag isSaveRawResponse in class construct
     *
     * @return string | null
     */
    public function getRawResponse(): ?string
    {
        return $this->rawResponse ?? null;
    }

    /**
     * get retries to connect timeout in microseconds
     *
     * @return mixed
     */
    public function getRetriesToConnectTimeout()
    {
        return $this->retriesToConnectTimeout;
    }

    /**
     * set retries to connect timeout in microseconds
     *
     * @param  int  $microseconds
     *
     * @return self
     */
    public function setRetriesToConnectTimeout(int $microseconds = 1000000): self
    {
        $this->log->debug(sprintf('set retries to connect timeout %s', $microseconds));
        $this->retriesToConnectTimeout = $microseconds;
        return $this;
    }

    /**
     * Handling bitrix24 api-level errors
     *
     * @param       $arRequestResult
     * @param       $methodName
     * @param  array  $additionalParameters
     *
     * @return null
     *
     * @throws Exception
     */
    protected function handleBitrix24APILevelErrors(
        $arRequestResult,
        $methodName,
        array $additionalParameters = []
    ) {
        if (array_key_exists('error', $arRequestResult)) {
            $errorMsg = sprintf(
                '%s - %s in call [%s] for domain [%s]',
                $arRequestResult['error'],
                (array_key_exists('error_description', $arRequestResult) ? $arRequestResult['error_description'] : ''),
                $methodName,
                $this->getDomain()
            );
            // logging error
            $this->log->error($errorMsg, $this->getErrorContext());

            // throw specific API-level exceptions
            switch (strtoupper(trim($arRequestResult['error']))) {
                case 'WRONG_CLIENT':
                case 'ERROR_OAUTH':
                    throw new Bitrix24WrongClientException($errorMsg);
                case 'ERROR_METHOD_NOT_FOUND':
                    throw new Bitrix24MethodNotFoundException($errorMsg);
                case 'INVALID_TOKEN':
                case 'INVALID_GRANT':
                    throw new Bitrix24TokenIsInvalidException($errorMsg);
                case 'EXPIRED_TOKEN':
                    throw new Bitrix24TokenIsExpiredException($errorMsg);
                case 'PAYMENT_REQUIRED':
                    throw new Bitrix24PaymentRequiredException($errorMsg);
                case 'NO_AUTH_FOUND':
                    throw new Bitrix24PortalRenamedException($errorMsg);
                case 'INSUFFICIENT_SCOPE':
                    throw new Bitrix24InsufficientScope($errorMsg);
                case 'ACCESS_DENIED':
                    throw new Bitrix24RestApiUnavailableOnFreeTariffException($errorMsg);
                default:
                    throw new Bitrix24ApiException($errorMsg);
            }
        }

        return null;
    }

    /**
     * get CURL request count retries
     *
     * @return int
     */
    public function getRetriesToConnectCount(): int
    {
        return $this->retriesToConnectCount;
    }

    /**
     * set CURL request count retries
     *
     * @param $retriesCnt
     *
     * @return self
     */
    public function setRetriesToConnectCount(int $retriesCnt = 1): self
    {
        $this->log->debug(sprintf('set retries to connect count %s', $retriesCnt));
        $this->retriesToConnectCount = $retriesCnt;
        return $this;
    }

    /**
     * Execute Bitrix24 REST API method
     *
     * @param  string  $methodName
     * @param  array  $additionalParameters
     *
     * @return mixed
     * @throws Exception
     */
    public function call($methodName, array $additionalParameters = [])
    {
        try {
            $result = $this->getWebhookUsage() ? $this->_call_webhook($methodName,
                $additionalParameters) : $this->_call($methodName, $additionalParameters);

            if (is_callable($this->_onCallApiMethod)) {
                call_user_func($this->_onCallApiMethod, $this, $methodName);
            }
        } catch (Bitrix24TokenIsExpiredException $e) {
            if (!is_callable($this->_onExpiredToken)) {
                throw $e;
            }

            $retry = call_user_func($this->_onExpiredToken, $this);
            if (!$retry) {
                throw $e;
            }

            $result = $this->getWebhookUsage() ? $this->_call_webhook($methodName,
                $additionalParameters) : $this->_call($methodName, $additionalParameters);
        }

        return $result;
    }

    /**
     * Execute Bitrix24 REST API method
     *
     * @param  string  $methodName
     * @param  array  $additionalParameters
     *
     * @return array
     * @throws Exception
     *
     */
    protected function _call(string $methodName, array $additionalParameters = [])
    {
        if (null === $this->getDomain()) {
            throw new Bitrix24Exception('domain not found, you must call setDomain method before');
        }
        if (null === $this->getAccessToken()) {
            throw new Bitrix24Exception('access token not found, you must call setAccessToken method before');
        }

        $url = 'https://'.$this->domain.'/rest/'.$methodName;
        $additionalParameters['auth'] = $this->accessToken;
        // save method parameters for debug
        $this->methodParameters = $additionalParameters;
        // is secure api-call?
        $isSecureCall = false;
        if (array_key_exists('state', $additionalParameters)) {
            $isSecureCall = true;
        }

        // execute request
        $this->log->info('call bitrix24 method', [
            'BITRIX24_DOMAIN' => $this->domain,
            'METHOD_NAME' => $methodName,
            'METHOD_PARAMETERS' => $additionalParameters,
        ]);
        $requestResult = $this->executeRequest($url, $additionalParameters);
        // check errors and throw exception if errors exists
        $this->handleBitrix24APILevelErrors($requestResult, $methodName, $additionalParameters);
        // handling security sign for secure api-call
        if ($isSecureCall) {
            if (array_key_exists('signature', $requestResult)) {
                // check signature structure
                if (strpos($requestResult['signature'], '.') === false) {
                    throw new Bitrix24SecurityException('security signature is corrupted');
                }
                if (null === $this->getMemberId()) {
                    throw new Bitrix24Exception('member-id not found, you must call setMemberId method before');
                }
                if (null === $this->getApplicationSecret()) {
                    throw new Bitrix24Exception('application secret not found, you must call setApplicationSecret method before');
                }
                // prepare
                $key = md5($this->getMemberId().$this->getApplicationSecret());
                $delimiterPosition = strrpos($requestResult['signature'], '.');
                $dataToDecode = substr($requestResult['signature'], 0, $delimiterPosition);
                $signature = base64_decode(substr($requestResult['signature'], $delimiterPosition + 1));
                // compare signatures
                $hash = hash_hmac('sha256', $dataToDecode, $key, true);

                if ($hash !== $signature) {
                    throw new Bitrix24SecurityException('security signatures not same, bad request');
                }
                // decode
                $arClearData = json_decode(base64_decode($dataToDecode), true);

                // handling json_decode errors
                $jsonErrorCode = json_last_error();
                if (null === $arClearData && (JSON_ERROR_NONE !== $jsonErrorCode)) {
                    $errorMsg = 'fatal error in function json_decode.'.PHP_EOL.'Error code: '.$jsonErrorCode.PHP_EOL.'Error message: '.json_last_error_msg().PHP_EOL;

                    // TODO: If more - use switch
                    if ($jsonErrorCode === JSON_ERROR_SYNTAX) {
                        throw new Bitrix24BadJsonResponseException($errorMsg);
                    }

                    throw new Bitrix24Exception($errorMsg);
                }
                // merge dirty and clear data
                unset($arClearData['state']);
                $requestResult['result'] = array_merge($requestResult['result'], $arClearData);
            } else {
                throw new Bitrix24SecurityException('security signature in api-response not found');
            }
        }

        return $requestResult;
    }
}