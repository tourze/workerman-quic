<?php

namespace Tourze\Workerman\QUIC\Service;

class Packet
{
    /**
     * 包头标志位
     * @var int
     */
    private $_flags;

    /**
     * QUIC 版本
     * @var int
     */
    private $_version;

    /**
     * 目标连接 ID
     * @var string
     */
    private $_destinationConnectionId;

    /**
     * 源连接 ID
     * @var string
     */
    private $_sourceConnectionId;

    /**
     * 包号
     * @var int
     */
    private $_packetNumber;

    /**
     * 包负载
     * @var string
     */
    private $_payload;

    /**
     * 构造函数
     * @param int $flags
     * @param int $version
     * @param string $destConnId
     * @param string $srcConnId
     * @param int $packetNumber
     * @param string $payload
     */
    public function __construct(
        int $flags,
        int $version,
        string $destConnId,
        string $srcConnId,
        int $packetNumber,
        string $payload = ''
    ) {
        $this->_flags = $flags;
        $this->_version = $version;
        $this->_destinationConnectionId = $destConnId;
        $this->_sourceConnectionId = $srcConnId;
        $this->_packetNumber = $packetNumber;
        $this->_payload = $payload;
    }

    /**
     * 编码包
     * @return string
     */
    public function encode(): string
    {
        $buffer = '';
        
        // 包头
        $buffer .= chr($this->_flags);
        $buffer .= pack('N', $this->_version);
        
        // 连接 ID 长度
        $buffer .= chr(strlen($this->_destinationConnectionId));
        $buffer .= chr(strlen($this->_sourceConnectionId));
        
        // 连接 ID
        $buffer .= $this->_destinationConnectionId;
        $buffer .= $this->_sourceConnectionId;
        
        // 包号 (变长编码)
        $buffer .= $this->encodePacketNumber($this->_packetNumber);
        
        // 负载
        $buffer .= $this->_payload;
        
        return $buffer;
    }

    /**
     * 解码包
     * @param string $data
     * @return Packet
     */
    public static function decode(string $data): Packet
    {
        $offset = 0;
        
        // 解析包头
        $flags = ord($data[$offset++]);
        $version = unpack('N', substr($data, $offset, 4))[1];
        $offset += 4;
        
        // 解析连接 ID 长度
        $destConnIdLen = ord($data[$offset++]);
        $srcConnIdLen = ord($data[$offset++]);
        
        // 解析连接 ID
        $destConnId = substr($data, $offset, $destConnIdLen);
        $offset += $destConnIdLen;
        $srcConnId = substr($data, $offset, $srcConnIdLen);
        $offset += $srcConnIdLen;
        
        // 解析包号
        list($packetNumber, $bytesRead) = self::decodePacketNumber($data, $offset);
        $offset += $bytesRead;
        
        // 解析负载
        $payload = substr($data, $offset);
        
        return new self($flags, $version, $destConnId, $srcConnId, $packetNumber, $payload);
    }

    /**
     * 编码包号
     * @param int $number
     * @return string
     */
    private function encodePacketNumber(int $number): string
    {
        if ($number < 0x40) {
            return chr($number);
        } elseif ($number < 0x4000) {
            return pack('n', $number | 0x4000);
        } elseif ($number < 0x40000000) {
            return pack('N', $number | 0x80000000);
        } else {
            return pack('J', $number | 0xC000000000000000);
        }
    }

    /**
     * 解码包号
     * @param string $data
     * @param int $offset
     * @return array [number, bytesRead]
     */
    private static function decodePacketNumber(string $data, int $offset): array
    {
        $firstByte = ord($data[$offset]);
        $prefix = $firstByte >> 6;
        
        switch ($prefix) {
            case 0:
                return [$firstByte & 0x3F, 1];
            case 1:
                $value = unpack('n', substr($data, $offset, 2))[1];
                return [$value & 0x3FFF, 2];
            case 2:
                $value = unpack('N', substr($data, $offset, 4))[1];
                return [$value & 0x3FFFFFFF, 4];
            case 3:
                $value = unpack('J', substr($data, $offset, 8))[1];
                return [$value & 0x3FFFFFFFFFFFFFFF, 8];
        }
        throw new \RuntimeException('未知的 prefix：' . $prefix);
    }

    // Getters
    public function getFlags(): int
    {
        return $this->_flags;
    }

    public function getVersion(): int
    {
        return $this->_version;
    }

    public function getDestinationConnectionId(): string
    {
        return $this->_destinationConnectionId;
    }

    public function getSourceConnectionId(): string
    {
        return $this->_sourceConnectionId;
    }

    public function getPacketNumber(): int
    {
        return $this->_packetNumber;
    }

    public function getPayload(): string
    {
        return $this->_payload;
    }
} 