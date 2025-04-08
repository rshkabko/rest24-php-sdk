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

    /**
     * When we need to set proxy to domain zone or domain.
     *
     * Ex: setProxyToDomainZone(['domain.com' => 'proxy:port', 'com' => 'proxy:port']);
     *
     * @param  array|null  $zones
     * @return \Bitrix24\Bitrix24|Proxy
     */
    public function setProxyToDomainZone(?array $zones = null): self
    {
        if (is_null($zones) || empty($zones)) {
            return $this;
        }

        // Mayby for domain?
        if (isset($zones[$this->getDomain()])) {
            $this->setProxy($zones[$this->getDomain()]);
            return $this;
        }

        $parts = explode('.', $this->getDomain());
        if (isset($zones[end($parts)])) {
            $this->setProxy($zones[end($parts)]);
        }

        return $this;
    }
}
