<?php

namespace Tourze\Workerman\QUIC\Enum;

enum StreamSendState
{
    case READY;      // 准备发送
    case SEND;       // 正在发送
    case DATA_SENT;  // 数据已发送
    case RESET_SENT; // 已发送重置
    case RESET_RECVD;// 已收到重置确认

    /**
     * 判断是否可以发送数据
     */
    public function canSendData(): bool
    {
        return match($this) {
            self::READY, self::SEND, self::DATA_SENT => true,
            default => false
        };
    }
}
