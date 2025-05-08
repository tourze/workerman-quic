<?php

namespace Tourze\Workerman\QUIC\Enum;

enum FrameType: int
{
    case PADDING = 0x00;
    case PING = 0x01;
    case ACK = 0x02;
    case RESET_STREAM = 0x04;
    case STOP_SENDING = 0x05;
    case CRYPTO = 0x06;
    case NEW_TOKEN = 0x07;
    case STREAM = 0x08;
    case MAX_DATA = 0x10;
    case MAX_STREAM_DATA = 0x11;
    case MAX_STREAMS = 0x12;
    case MAX_STREAMS_UNI = 0x13;
    case DATA_BLOCKED = 0x14;
    case STREAM_DATA_BLOCKED = 0x15;
    case STREAMS_BLOCKED = 0x16;
    case STREAMS_BLOCKED_UNI = 0x17;
    case NEW_CONNECTION_ID = 0x18;
    case RETIRE_CONNECTION_ID = 0x19;
    case PATH_CHALLENGE = 0x1A;
    case PATH_RESPONSE = 0x1B;
    case CONNECTION_CLOSE = 0x1C;
    case HANDSHAKE_DONE = 0x1E;
    case PONG = 0x1F;
    case PREFERRED_ADDRESS = 0x20;

    /**
     * 判断帧类型是否需要长度字段
     */
    public function needsLength(): bool
    {
        return !in_array($this, [
            self::PADDING,
            self::PING,
            self::ACK
        ]);
    }

    /**
     * 判断是否为流控制帧
     */
    public function isFlowControl(): bool
    {
        return in_array($this, [
            self::MAX_DATA,
            self::MAX_STREAM_DATA,
            self::MAX_STREAMS,
            self::DATA_BLOCKED,
            self::STREAM_DATA_BLOCKED,
            self::STREAMS_BLOCKED
        ]);
    }

    /**
     * 判断是否为连接管理帧
     */
    public function isConnectionControl(): bool
    {
        return in_array($this, [
            self::NEW_CONNECTION_ID,
            self::RETIRE_CONNECTION_ID,
            self::PATH_CHALLENGE,
            self::PATH_RESPONSE,
            self::CONNECTION_CLOSE
        ]);
    }
}
