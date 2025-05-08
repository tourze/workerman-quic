<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\PacketType;
use Workerman\Connection\ConnectionInterface;
use Workerman\Protocols\ProtocolInterface;

class QUICProtocol implements ProtocolInterface
{
    // QUIC 版本号 (Version 1)
    const VERSION = 0x00000001;

    // TLS 相关常量
    const TLS_AES_128_GCM_SHA256 = 0x1301;
    const TLS_AES_256_GCM_SHA384 = 0x1302;
    const TLS_CHACHA20_POLY1305_SHA256 = 0x1303;

    // QUIC 连接状态
    private $_state = 'idle';

    // 连接 ID
    private $_connectionId;

    // TLS 上下文
    private $_tlsContext;

    /**
     * 检查包的完整性
     * @param string $buffer
     * @param ConnectionInterface $connection
     * @return int
     */
    public static function input(string $buffer, ConnectionInterface $connection): int
    {
        if (strlen($buffer) < 20) {
            return 0;
        }

        // 解析 QUIC 包头
        $header = unpack('Cflags/Nversion', $buffer);
        $offset = 5;

        // 检查版本号
        if ($header['version'] !== self::VERSION && $header['flags'] !== PacketType::VERSION_NEGOTIATION->value) {
            return 0;
        }

        // 获取连接 ID 长度
        $destConnIdLen = ord($buffer[$offset++]);
        $srcConnIdLen = ord($buffer[$offset++]);

        // 跳过连接 ID
        $offset += $destConnIdLen + $srcConnIdLen;

        // 如果是长包头,解析包号长度
        $isLongHeader = ($header['flags'] & 0x80) !== 0;
        if ($isLongHeader) {
            // 变长整数编码的包长度
            list($length, $bytesRead) = self::decodeVariableInt(substr($buffer, $offset));
            $offset += $bytesRead;
            
            // 包号长度
            $packetNumberLength = ($header['flags'] & 0x03) + 1;
            
            // 计算总长度
            $totalLength = $offset + $packetNumberLength + $length;
            
            // 如果数据不完整,继续等待
            if (strlen($buffer) < $totalLength) {
                return 0;
            }
            
            return $totalLength;
        } else {
            // 短包头,直接返回剩余数据长度
            return strlen($buffer);
        }
    }

    /**
     * 打包要发送的数据
     * @param mixed $data
     * @param ConnectionInterface $connection
     * @return string
     */
    public static function encode(mixed $data, ConnectionInterface $connection): string
    {
        if ($data instanceof Packet) {
            return $data->encode();
        }
        
        // 如果是普通数据,创建一个 1-RTT 包
        $packet = new Packet(
            0x30, // 1-RTT 包类型
            self::VERSION,
            $connection->quicConnection->getRemoteConnectionId(),
            $connection->quicConnection->getLocalConnectionId(),
            $connection->quicConnection->getNextPacketNumber(),
            (string)$data
        );
        
        return $packet->encode();
    }

    /**
     * 解包接收到的数据
     * @param string $buffer
     * @param ConnectionInterface $connection
     * @return mixed
     */
    public static function decode(string $buffer, ConnectionInterface $connection): mixed
    {
        // 检查是否为版本协商包
        $header = unpack('Cflags/Nversion', $buffer);
        if ($header['flags'] === PacketType::VERSION_NEGOTIATION->value) {
            return self::handleVersionNegotiation($buffer);
        }

        // 检查版本号
        if ($header['version'] !== self::VERSION) {
            if (self::isReservedVersion($header['version'])) {
                throw new \Exception('Reserved version used');
            }
            // 发送版本协商包
            return self::generateVersionNegotiationPacket(
                $connection->quicConnection->getLocalConnectionId(),
                $connection->quicConnection->getRemoteConnectionId(),
                [self::VERSION]
            );
        }

        $packet = Packet::decode($buffer);
        
        // 如果连接还没有初始化
        if (!isset($connection->quicConnection)) {
            $connection->quicConnection = new Connection($connection);
        }
        
        // 处理包
        $connection->quicConnection->handlePacket($packet);
        
        return $packet;
    }

    /**
     * 解码变长整数
     * @param string $data
     * @return array [value, bytesRead]
     */
    private static function decodeVariableInt(string $data): array
    {
        $firstByte = ord($data[0]);
        $prefix = $firstByte >> 6;
        
        switch ($prefix) {
            case 0:
                return [$firstByte & 0x3F, 1];
            case 1:
                return [
                    (($firstByte & 0x3F) << 8) | ord($data[1]),
                    2
                ];
            case 2:
                return [
                    (($firstByte & 0x3F) << 24) | 
                    (ord($data[1]) << 16) | 
                    (ord($data[2]) << 8) | 
                    ord($data[3]),
                    4
                ];
            case 3:
                return [
                    (($firstByte & 0x3F) << 56) |
                    (ord($data[1]) << 48) |
                    (ord($data[2]) << 40) |
                    (ord($data[3]) << 32) |
                    (ord($data[4]) << 24) |
                    (ord($data[5]) << 16) |
                    (ord($data[6]) << 8) |
                    ord($data[7]),
                    8
                ];
            default:
                throw new \Exception('Invalid variable length integer prefix');
        }
    }

    /**
     * 处理版本协商
     */
    private static function handleVersionNegotiation(string $buffer): string
    {
        // 解析包头
        $header = unpack('Cflags/Nversion', $buffer);
        $offset = 5;

        // 获取连接 ID 长度
        $destConnIdLen = ord($buffer[$offset++]);
        $srcConnIdLen = ord($buffer[$offset++]);

        // 获取连接 ID
        $destConnId = substr($buffer, $offset, $destConnIdLen);
        $offset += $destConnIdLen;
        $srcConnId = substr($buffer, $offset, $srcConnIdLen);
        $offset += $srcConnIdLen;

        // 解析支持的版本列表
        $versions = [];
        while ($offset < strlen($buffer)) {
            $versions[] = unpack('N', substr($buffer, $offset, 4))[1];
            $offset += 4;
        }

        // 检查是否支持当前版本
        if (in_array(self::VERSION, $versions)) {
            return '';
        }

        // 生成版本协商包
        return self::generateVersionNegotiationPacket($destConnId, $srcConnId, $versions);
    }

    /**
     * 生成版本协商包
     * @param string $destConnId
     * @param string $srcConnId 
     * @param array $versions
     * @return string
     */
    private static function generateVersionNegotiationPacket(string $destConnId, string $srcConnId, array $versions): string
    {
        $packet = '';
        
        // 设置包头标志位 (版本协商包)
        $packet .= chr(PacketType::VERSION_NEGOTIATION->value);
        
        // 版本号设为 0
        $packet .= pack('N', 0);
        
        // 连接 ID 长度
        $packet .= chr(strlen($destConnId));
        $packet .= chr(strlen($srcConnId));
        
        // 连接 ID
        $packet .= $destConnId;
        $packet .= $srcConnId;
        
        // 支持的版本列表
        foreach ($versions as $version) {
            $packet .= pack('N', $version);
        }
        
        return $packet;
    }

    /**
     * 检查是否为保留版本
     * @param int $version
     * @return bool
     */
    private static function isReservedVersion(int $version): bool
    {
        // 检查最后一个字节是否为 0x0a
        return ($version & 0x0F0F0F0F) === 0x0a0a0a0a;
    }
}
