<?php

namespace Tourze\Workerman\QUIC\Enum;

enum ConnectionState: int
{
    case NEW = 0;
    case HANDSHAKING = 1;
    case CONNECTED = 2;
    case CLOSING = 3;
    case DRAINING = 4;
    case CLOSED = 5;

    /**
     * 判断是否可以发送数据
     */
    public function canSendData(): bool
    {
        return in_array($this, [
            self::CONNECTED
        ]);
    }

    /**
     * 判断是否可以接收数据
     */
    public function canReceiveData(): bool
    {
        return in_array($this, [
            self::CONNECTED
        ]);
    }

    /**
     * 判断是否正在握手
     */
    public function isHandshaking(): bool
    {
        return $this === self::HANDSHAKING;
    }

    /**
     * 判断是否已关闭
     */
    public function isClosed(): bool
    {
        return in_array($this, [
            self::CLOSING,
            self::DRAINING,
            self::CLOSED
        ]);
    }
}
