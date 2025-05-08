<?php

namespace Tourze\Workerman\QUIC\Enum;

enum StreamType
{
    case CLIENT_BIDIRECTIONAL;
    case SERVER_BIDIRECTIONAL;
    case CLIENT_UNIDIRECTIONAL;
    case SERVER_UNIDIRECTIONAL;

    public function value(): int
    {
        return match($this) {
            self::CLIENT_BIDIRECTIONAL => 0,
            self::SERVER_BIDIRECTIONAL => 1,
            self::CLIENT_UNIDIRECTIONAL => 2,
            self::SERVER_UNIDIRECTIONAL => 3,
        };
    }

    public static function fromStreamId(int $streamId): self
    {
        $type = $streamId & 0x03;
        return match($type) {
            0 => self::CLIENT_BIDIRECTIONAL,
            1 => self::SERVER_BIDIRECTIONAL,
            2 => self::CLIENT_UNIDIRECTIONAL,
            3 => self::SERVER_UNIDIRECTIONAL,
        };
    }

    /**
     * 判断是否为服务端发起的流
     * @param int $streamId
     * @return bool
     */
    public static function isServerInitiated(int $streamId): bool
    {
        return ($streamId & 0x1) === 1;
    }

    /**
     * 判断是否为单向流
     * @param int $streamId
     * @return bool
     */
    public static function isUnidirectional(int $streamId): bool
    {
        return ($streamId & 0x2) === 2;
    }

    /**
     * 生成流 ID
     * @param int $sequence 序列号
     * @return int
     */
    public function generateId(int $sequence): int
    {
        return ($sequence << 2) | $this->value();
    }

    /**
     * 判断当前类型是否为服务端发起
     */
    public function isServer(): bool
    {
        return $this === self::SERVER_BIDIRECTIONAL || $this === self::SERVER_UNIDIRECTIONAL;
    }

    /**
     * 判断当前类型是否为单向
     */
    public function isUni(): bool
    {
        return $this === self::CLIENT_UNIDIRECTIONAL || $this === self::SERVER_UNIDIRECTIONAL;
    }
}
