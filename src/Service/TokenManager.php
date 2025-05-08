<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\PacketType;

class TokenManager
{
    /**
     * 令牌密钥
     */
    private string $_tokenKey;

    /**
     * 地址验证令牌
     */
    private ?string $_retryToken = null;

    /**
     * 无状态重置令牌
     */
    private ?string $_statelessResetToken = null;

    /**
     * QUIC 连接实例
     */
    private Connection $_connection;

    public function __construct(Connection $connection, string $tokenKey)
    {
        $this->_connection = $connection;
        $this->_tokenKey = $tokenKey;
    }

    /**
     * 生成地址验证令牌
     */
    public function generateToken(string $clientAddress): string
    {
        $data = $clientAddress . pack('J', time());
        return hash_hmac('sha256', $data, $this->_tokenKey, true);
    }

    /**
     * 验证令牌
     */
    public function validateToken(string $token, string $clientAddress): bool
    {
        $timestamp = unpack('J', substr($token, -8))[1];
        
        if (time() - $timestamp > 600) {
            return false;
        }

        $expectedToken = $this->generateToken($clientAddress);
        return hash_equals($token, $expectedToken);
    }

    /**
     * 发送重试包
     */
    public function sendRetryPacket(string $clientAddress): void
    {
        $this->_retryToken = $this->generateToken($clientAddress);
        
        $packet = new Packet(
            PacketType::RETRY->value,
            QUICProtocol::VERSION,
            $this->_connection->getRemoteConnectionId(),
            $this->_connection->getLocalConnectionId(),
            0,
            $this->_retryToken
        );
        
        $this->_connection->send($packet->encode(), PacketType::RETRY);
    }

    /**
     * 生成无状态重置令牌
     */
    public function generateStatelessResetToken(): string
    {
        $data = $this->_connection->getLocalConnectionId() . pack('J', time());
        return hash_hmac('sha256', $data, $this->_tokenKey, true);
    }

    /**
     * 发送无状态重置
     */
    public function sendStatelessReset(): void
    {
        if (!$this->_statelessResetToken) {
            $this->_statelessResetToken = $this->generateStatelessResetToken();
        }

        $packet = random_bytes(16) . $this->_statelessResetToken;
        $this->_connection->send($packet, PacketType::RETRY);
    }

    /**
     * 验证无状态重置令牌
     */
    public function validateStatelessResetToken(string $token): bool
    {
        if (!$this->_statelessResetToken) {
            return false;
        }

        return hash_equals($token, $this->_statelessResetToken);
    }

    /**
     * 处理 NEW_TOKEN 帧
     */
    public function handleNewToken(string $data): void
    {
        if ($this->_connection->isServer()) {
            return;
        }

        $tokenLength = unpack('n', substr($data, 0, 2))[1];
        $token = substr($data, 2, $tokenLength);
        
        $this->_retryToken = $token;
    }
} 