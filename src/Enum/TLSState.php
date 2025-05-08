<?php

namespace Tourze\Workerman\QUIC\Enum;

enum TLSState: int
{
    case INITIAL = 0;
    case HANDSHAKING = 1;
    case ESTABLISHED = 2;
    case CLOSING = 3;
    case CLOSED = 4;

    /**
     * 判断是否可以发送数据
     */
    public function canSendData(): bool
    {
        return $this === self::ESTABLISHED;
    }

    /**
     * 判断是否可以接收数据
     */
    public function canReceiveData(): bool
    {
        return $this === self::ESTABLISHED;
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
        return $this === self::CLOSED || $this === self::CLOSING;
    }
}
