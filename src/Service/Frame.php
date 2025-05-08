<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\FrameType;

class Frame
{
    /**
     * 帧类型
     */
    private FrameType $_type;

    /**
     * 帧负载
     */
    private string $_payload;

    /**
     * 构造函数
     * @param FrameType $type
     * @param string $payload
     */
    public function __construct(FrameType $type, string $payload = '')
    {
        $this->_type = $type;
        $this->_payload = $payload;
    }

    /**
     * 获取帧类型
     */
    public function getType(): FrameType
    {
        return $this->_type;
    }

    /**
     * 获取帧负载
     */
    public function getPayload(): string
    {
        return $this->_payload;
    }

    /**
     * 编码帧
     */
    public function encode(): string
    {
        return chr($this->_type->value) . $this->_payload;
    }

    /**
     * 解码帧
     */
    public static function decode(string $data): self
    {
        $type = FrameType::from(ord($data[0]));
        $payload = substr($data, 1);
        return new self($type, $payload);
    }
} 