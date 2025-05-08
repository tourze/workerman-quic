<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\ConnectionState;
use Tourze\Workerman\QUIC\Enum\FrameType;
use Tourze\Workerman\QUIC\Enum\QuicError;

class StateManager
{
    /**
     * 当前状态
     */
    private ConnectionState $_state = ConnectionState::NEW;

    /**
     * 空闲超时时间(秒)
     */
    private int $_idleTimeout = 30;

    /**
     * 最后活动时间
     */
    private int $_lastActivityTime;

    /**
     * 关闭状态
     */
    private array $_closeState = [
        'error_code' => 0,
        'frame_type' => null,
        'reason' => '',
        'drain_timeout' => null
    ];

    /**
     * QUIC 连接实例
     */
    private Connection $_connection;

    public function __construct(Connection $connection)
    {
        $this->_connection = $connection;
        $this->_lastActivityTime = time();
    }

    /**
     * 获取当前状态
     */
    public function getState(): ConnectionState
    {
        return $this->_state;
    }

    /**
     * 设置状态
     */
    public function setState(ConnectionState $state): void
    {
        $this->_state = $state;
    }

    /**
     * 检查空闲超时
     */
    public function checkIdleTimeout(): bool
    {
        if ($this->_state === ConnectionState::CLOSED) {
            return false;
        }

        $now = time();
        if ($now - $this->_lastActivityTime > $this->_idleTimeout) {
            $this->close(QuicError::NO_ERROR->value, 'idle timeout');
            return true;
        }

        return false;
    }

    /**
     * 更新活动时间
     */
    public function updateLastActivityTime(): void
    {
        $this->_lastActivityTime = time();
    }

    /**
     * 发送 PING 帧
     */
    public function sendPing(): void
    {
        $frame = new Frame(FrameType::PING);
        $this->_connection->send($frame->encode(), FrameType::PING);
        $this->updateLastActivityTime();
    }

    /**
     * 延长空闲超时
     */
    public function extendIdleTimeout(int $timeout): void
    {
        $this->_idleTimeout = $timeout;
        $this->updateLastActivityTime();
    }

    /**
     * 立即关闭连接
     */
    public function close(int $errorCode = 0, string $reason = '', ?int $frameType = null): void
    {
        if ($this->_state === ConnectionState::CLOSED) {
            return;
        }

        $this->_closeState = [
            'error_code' => $errorCode,
            'frame_type' => $frameType,
            'reason' => $reason,
            'drain_timeout' => time() + 3 * $this->_idleTimeout
        ];

        $frameData = pack('N', $errorCode);
        if ($frameType !== null) {
            $frameData .= pack('N', $frameType);
        }
        $frameData .= pack('n', strlen($reason)) . $reason;

        $frame = new Frame(FrameType::CONNECTION_CLOSE, $frameData);
        $this->_connection->send($frame->encode(), FrameType::CONNECTION_CLOSE);

        $this->_state = ConnectionState::CLOSING;
        $this->startDraining();
    }

    /**
     * 开始排空状态
     */
    private function startDraining(): void
    {
        $this->_state = ConnectionState::DRAINING;
    }

    /**
     * 处理 CONNECTION_CLOSE 帧
     */
    public function handleConnectionClose(Frame $frame): void
    {
        $data = $frame->getPayload();
        $errorCode = unpack('N', substr($data, 0, 4))[1];
        $offset = 4;

        $frameType = null;
        if ($frame->getType() === FrameType::CONNECTION_CLOSE) {
            $frameType = unpack('N', substr($data, $offset, 4))[1];
            $offset += 4;
        }

        $reasonLength = unpack('n', substr($data, $offset, 2))[1];
        $offset += 2;
        $reason = substr($data, $offset, $reasonLength);

        $this->_closeState = [
            'error_code' => $errorCode,
            'frame_type' => $frameType,
            'reason' => $reason,
            'drain_timeout' => time() + 3 * $this->_idleTimeout
        ];

        $this->_state = ConnectionState::CLOSING;
        $this->startDraining();
        $this->close($errorCode, $reason, $frameType);
    }
} 