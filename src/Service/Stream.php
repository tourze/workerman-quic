<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\FrameType;
use Tourze\Workerman\QUIC\Enum\QuicError;
use Tourze\Workerman\QUIC\Enum\StreamRecvState;
use Tourze\Workerman\QUIC\Enum\StreamSendState;
use Tourze\Workerman\QUIC\Enum\StreamType;

class Stream
{
    /**
     * 流 ID
     */
    private int $_id;

    /**
     * 发送状态
     */
    private StreamSendState $_sendState = StreamSendState::READY;

    /**
     * 接收状态
     */
    private StreamRecvState $_recvState = StreamRecvState::RECV;

    /**
     * 发送缓冲区
     */
    private string $_sendBuffer = '';

    /**
     * 接收缓冲区
     */
    private array $_recvBuffer = [];

    /**
     * 已接收的最大偏移量
     */
    private int $_maxRecvOffset = 0;

    /**
     * 已发送的最大偏移量
     */
    private int $_maxSendOffset = 0;

    /**
     * 最大发送数据量
     */
    private int $_maxSendData = 1048576; // 1MB

    /**
     * 最大接收数据量
     */
    private int $_maxRecvData = 1048576; // 1MB

    /**
     * 是否是最终帧
     */
    private bool $_isFinal = false;

    /**
     * QUIC 连接实例
     */
    private Connection $_connection;

    public function __construct(int $id, Connection $connection)
    {
        $this->_id = $id;
        $this->_connection = $connection;
    }

    /**
     * 获取流 ID
     */
    public function getId(): int
    {
        return $this->_id;
    }

    /**
     * 获取流类型
     */
    public function getType(): StreamType
    {
        return StreamType::fromStreamId($this->_id);
    }

    /**
     * 发送数据
     */
    public function send(string $data, bool $isFinal = false): void
    {
        if ($this->_sendState !== StreamSendState::READY && $this->_sendState !== StreamSendState::SEND) {
            throw new \Exception('Stream not ready for sending', QuicError::STREAM_STATE_ERROR->value);
        }

        $this->_sendBuffer .= $data;
        $this->_isFinal = $isFinal;
        $this->_sendState = StreamSendState::SEND;

        $this->trySend();
    }

    /**
     * 尝试发送数据
     */
    private function trySend(): void
    {
        if ($this->_sendState !== StreamSendState::SEND || empty($this->_sendBuffer)) {
            return;
        }

        $maxChunkSize = min(1200, $this->_maxSendData - $this->_maxSendOffset);
        if ($maxChunkSize <= 0) {
            return;
        }

        $chunk = substr($this->_sendBuffer, 0, $maxChunkSize);
        $this->_sendBuffer = substr($this->_sendBuffer, $maxChunkSize);

        $frame = new Frame(FrameType::STREAM, $this->encodeStreamData($chunk));
        $this->_connection->send($frame->encode(), FrameType::STREAM);

        $this->_maxSendOffset += strlen($chunk);

        if (empty($this->_sendBuffer)) {
            if ($this->_isFinal) {
                $this->_sendState = StreamSendState::DATA_SENT;
            } else {
                $this->_sendState = StreamSendState::READY;
            }
        }
    }

    /**
     * 接收数据
     */
    public function receive(string $data, int $offset, bool $isFinal): void
    {
        if ($this->_recvState !== StreamRecvState::RECV && $this->_recvState !== StreamRecvState::SIZE_KNOWN) {
            throw new \Exception('Stream not ready for receiving', QuicError::STREAM_STATE_ERROR->value);
        }

        if ($offset + strlen($data) > $this->_maxRecvData) {
            throw new \Exception('Stream data limit exceeded', QuicError::FLOW_CONTROL_ERROR->value);
        }

        $this->_recvBuffer[$offset] = $data;
        $this->_maxRecvOffset = max($this->_maxRecvOffset, $offset + strlen($data));

        if ($isFinal) {
            $this->_recvState = StreamRecvState::SIZE_KNOWN;
        }

        $this->tryRead();
    }

    /**
     * 尝试读取数据
     */
    private function tryRead(): void
    {
        if (empty($this->_recvBuffer)) {
            return;
        }

        ksort($this->_recvBuffer);
        $expectedOffset = 0;
        $data = '';

        foreach ($this->_recvBuffer as $offset => $chunk) {
            if ($offset !== $expectedOffset) {
                break;
            }

            $data .= $chunk;
            $expectedOffset += strlen($chunk);
            unset($this->_recvBuffer[$offset]);
        }

        if (!empty($data)) {
            $this->_connection->onStreamData($this->_id, $data);
        }

        if ($this->_recvState === StreamRecvState::SIZE_KNOWN && empty($this->_recvBuffer)) {
            $this->_recvState = StreamRecvState::DATA_RECVD;
            $this->_connection->onStreamEnd($this->_id);
        }
    }

    /**
     * 处理流重置
     */
    public function handleResetStream(): void
    {
        $this->_sendState = StreamSendState::RESET_RECVD;
        $this->_sendBuffer = '';
    }

    /**
     * 处理停止发送
     */
    public function handleStopSending(): void
    {
        $this->_sendState = StreamSendState::RESET_SENT;
        $this->_sendBuffer = '';

        $frame = new Frame(FrameType::RESET_STREAM, pack('N', $this->_id));
        $this->_connection->send($frame->encode(), FrameType::RESET_STREAM);
    }

    /**
     * 更新最大发送数据量
     */
    public function updateMaxSendData(int $maxData): void
    {
        $this->_maxSendData = $maxData;
        $this->trySend();
    }

    /**
     * 编码流数据
     */
    private function encodeStreamData(string $data): string
    {
        $streamId = $this->encodeVariableInt($this->_id);
        $offset = $this->encodeVariableInt($this->_maxSendOffset);
        $length = $this->encodeVariableInt(strlen($data));

        return $streamId . $offset . $length . $data;
    }

    /**
     * 编码变长整数
     */
    private function encodeVariableInt(int $value): string
    {
        if ($value <= 0x3F) {
            return chr($value);
        } elseif ($value <= 0x3FFF) {
            return chr(0x40 | ($value >> 8)) . chr($value & 0xFF);
        } elseif ($value <= 0x3FFFFFFF) {
            return chr(0x80 | ($value >> 24)) . 
                   chr(($value >> 16) & 0xFF) . 
                   chr(($value >> 8) & 0xFF) . 
                   chr($value & 0xFF);
        } else {
            return chr(0xC0 | ($value >> 56)) . 
                   chr(($value >> 48) & 0xFF) . 
                   chr(($value >> 40) & 0xFF) . 
                   chr(($value >> 32) & 0xFF) . 
                   chr(($value >> 24) & 0xFF) . 
                   chr(($value >> 16) & 0xFF) . 
                   chr(($value >> 8) & 0xFF) . 
                   chr($value & 0xFF);
        }
    }
}
