<?php

namespace Tourze\Workerman\QUIC\Enum;

enum PacketType: int
{
    case INITIAL = 0x00;
    case ZERO_RTT = 0x01;
    case HANDSHAKE = 0x02;
    case RETRY = 0x03;
    case VERSION_NEGOTIATION = 0xFF;

    /**
     * 判断是否为长包头
     */
    public function isLongHeader(): bool
    {
        return in_array($this, [
            self::INITIAL,
            self::ZERO_RTT,
            self::HANDSHAKE,
            self::RETRY,
            self::VERSION_NEGOTIATION
        ]);
    }

    /**
     * 判断是否为加密包
     */
    public function isEncrypted(): bool
    {
        return in_array($this, [
            self::ZERO_RTT,
            self::HANDSHAKE
        ]);
    }

    /**
     * 获取包类型名称
     */
    public function getName(): string
    {
        return match($this) {
            self::INITIAL => 'Initial',
            self::ZERO_RTT => 'Zero RTT',
            self::HANDSHAKE => 'Handshake',
            self::RETRY => 'Retry',
            self::VERSION_NEGOTIATION => 'Version Negotiation'
        };
    }
} 