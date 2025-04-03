<?php

namespace Bitrix24\Traits;

use Bitrix24\Exceptions\Bitrix24Exception;

trait Batch
{
    /**
     * @var int max batch calls
     */
    const MAX_BATCH_CALLS = 50;

    /**
     * @var int batch delay in microseconds
     */
    const BATCH_DELAY = 500000;

    /**
     * @var array pending batch calls
     */
    protected array $_batch = [];

    /**
     * Add call to batch. If [[$callback]] parameter is set, it will receive call result as first parameter.
     *
     * @param  string  $method
     * @param  array  $parameters
     * @param  callable|null  $callback
     *
     * @return string Unique call ID.
     */
    public function addBatchCall($method, array $parameters = [], callable $callback = null)
    {
        $id = uniqid('', true);
        $this->_batch[$id] = [
            'method' => $method,
            'parameters' => $parameters,
            'callback' => $callback,
        ];

        return $id;
    }

    /**
     * Return true, if we have unprocessed batch calls.
     *
     * @return bool
     */
    public function hasBatchCalls(): bool
    {
        return (bool) count($this->_batch);
    }

    /**
     * Process batch calls.
     *
     * @param  int  $halt  Halt batch on error
     * @param  int  $delay  Delay between batch calls (in msec)
     *
     * @throws Exception
     */
    public function processBatchCalls($halt = 0, $delay = self::BATCH_DELAY)
    {
        $this->log->info('Bitrix24PhpSdk.processBatchCalls.start', ['batch_query_delay' => $delay]);
        $batchQueryCounter = 0;
        while (count($this->_batch)) {
            $batchQueryCounter++;
            $slice = array_splice($this->_batch, 0, self::MAX_BATCH_CALLS);
            $this->log->info('bitrix24PhpSdk.processBatchCalls.callItem', [
                'batch_query_number' => $batchQueryCounter,
            ]);

            $commands = [];
            foreach ($slice as $idx => $call) {
                $commands[$idx] = $call['method'].'?'.http_build_query($call['parameters']);
            }

            $batchResult = $this->call('batch', ['halt' => $halt, 'cmd' => $commands]);
            $results = $batchResult['result'];
            foreach ($slice as $idx => $call) {
                if (!isset($call['callback']) || !is_callable($call['callback'])) {
                    continue;
                }

                call_user_func($call['callback'], [
                    'result' => isset($results['result'][$idx]) ? $results['result'][$idx] : null,
                    'error' => isset($results['result_error'][$idx]) ? $results['result_error'][$idx] : null,
                    'total' => isset($results['result_total'][$idx]) ? $results['result_total'][$idx] : null,
                    'next' => isset($results['result_next'][$idx]) ? $results['result_next'][$idx] : null,
                ]);
            }
            if (count($this->_batch) && $delay) {
                usleep($delay);
            }
        }
        $this->log->info('bitrix24PhpSdk.processBatchCalls.finish');
    }

    /**
     *  Call Raw Batch request.
     *
     *  Example:
     *  $batch = [
     *      'step_0' => ['method' => 'crm.lead.list', 'params' => ['select' => ['ID', 'NAME'], 'filter' => ['>=ID' => 0]],
     *      'step_1' => ['method' => 'crm.lead.list', 'params' => ['select' => ['ID', 'NAME'], 'filter' => ['>=ID' => $result[step_0][49][ID]]],
     *  ];
     *
     * @param  array  $batch
     * @param $halt
     * @return array|mixed
     * @throws Exception
     */
    public function rawBatch(array $batch, $halt = 0)
    {
        if (count($batch) > self::MAX_BATCH_CALLS) {
            throw new Exception('Max batch call 50, you add '.count($batch));
        }

        foreach ($batch as $cmd) {
            if (!isset($cmd['method'])) {
                throw new Exception('Batch mast have method and params array!');
            }

            $commands = $cmd['method'].'?'.http_build_query($cmd['params'] ?? []);
        }

        return $this->call('batch', ['halt' => $halt, 'cmd' => $commands]);
    }
}
