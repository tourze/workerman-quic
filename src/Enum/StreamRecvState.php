<?php

namespace Tourze\Workerman\QUIC\Enum;

enum StreamRecvState: string
{
    case RECV = 'recv';             // 可以接收数据
    case SIZE_KNOWN = 'size_known'; // 已知最终大小
    case DATA_RECVD = 'data_recvd'; // 已接收所有数据
    case RESET_RECVD = 'reset_recvd'; // 收到 RESET_STREAM
    case RESET_READ = 'reset_read';   // 应用已读取 RESET

    /**
     * 判断是否可以接收数据
     */
    public function canReceiveData(): bool
    {
        return match($this) {
            self::RECV, self::SIZE_KNOWN => true,
            default => false
        };
    }
}
