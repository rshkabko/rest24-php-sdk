<?php

namespace Bitrix24\Traits;

use Bitrix24\Exceptions\Bitrix24Exception;

trait Proxy
{
    /**
     * Proxy IP:PORT
     *
     * @var string|null
     */
    protected ?string $proxy = null;

    /**
     * Get the proxy.
     *
     * @return string|null
     */
    protected function getProxy(): ?string
    {
        return $this->proxy;
    }

    /**
     * Set the proxy.
     *
     * @param  string  $proxy
     * @param  callable|null  $when We can check domain or other conditions.
     * @return self
     */
    public function setProxy(string $proxy, ?callable $when = null): self
    {
        if (is_null($when) || $when($this)) {
            $this->proxy = $proxy;
        }

        return $this;
    }
}
