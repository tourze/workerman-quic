<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\FrameType;
use Tourze\Workerman\QUIC\Enum\QuicError;
use Tourze\Workerman\QUIC\Enum\StreamType;

class StreamManager
{
    /**
     * 活动流列表
     * @var array<int, Stream>
     */
    private array $_streams = [];

    /**
     * 下一个流 ID
     */
    private array $_nextStreamId = [
        StreamType::CLIENT_BIDIRECTIONAL->value => 0,
        StreamType::SERVER_BIDIRECTIONAL->value => 1,
        StreamType::CLIENT_UNIDIRECTIONAL->value => 2,
        StreamType::SERVER_UNIDIRECTIONAL->value => 3,
    ];

    /**
     * 最大流数量限制
     */
    private array $_maxStreams = [
        StreamType::CLIENT_BIDIRECTIONAL->value => 100,
        StreamType::SERVER_BIDIRECTIONAL->value => 100,
        StreamType::CLIENT_UNIDIRECTIONAL->value => 100,
        StreamType::SERVER_UNIDIRECTIONAL->value => 100,
    ];

    /**
     * 流数据限制
     */
    private array $_maxStreamData = [
        StreamType::CLIENT_BIDIRECTIONAL->value => 1048576, // 1MB
        StreamType::SERVER_BIDIRECTIONAL->value => 1048576,
        StreamType::CLIENT_UNIDIRECTIONAL->value => 1048576,
        StreamType::SERVER_UNIDIRECTIONAL->value => 1048576,
    ];

    /**
     * QUIC 连接实例
     */
    private Connection $_connection;

    public function __construct(Connection $connection)
    {
        $this->_connection = $connection;
    }

    /**
     * 创建新流
     */
    public function createStream(StreamType $type): Stream
    {
        // 检查是否达到流限制
        if (count($this->getStreams($type)) >= $this->_maxStreams[$type->value]) {
            throw new \Exception('Stream limit reached', QuicError::STREAM_LIMIT_ERROR->value);
        }

        $streamId = $this->_nextStreamId[$type->value];
        $this->_nextStreamId[$type->value] += 4;

        $stream = new Stream($streamId, $this->_connection);
        $this->_streams[$streamId] = $stream;

        return $stream;
    }

    /**
     * 获取流
     */
    public function getStream(int $streamId): ?Stream
    {
        return $this->_streams[$streamId] ?? null;
    }

    /**
     * 获取指定类型的所有流
     */
    public function getStreams(StreamType $type): array
    {
        return array_filter($this->_streams, function(Stream $stream) use ($type) {
            return $stream->getType() === $type;
        });
    }

    /**
     * 处理 STREAM 帧
     */
    public function handleStreamFrame(Frame $frame): void
    {
        $data = $frame->getPayload();
        $offset = 0;

        // 解析流 ID
        list($streamId, $bytesRead) = $this->decodeVariableInt(substr($data, $offset));
        $offset += $bytesRead;

        // 解析偏移量
        list($streamOffset, $bytesRead) = $this->decodeVariableInt(substr($data, $offset));
        $offset += $bytesRead;

        // 解析数据长度
        list($length, $bytesRead) = $this->decodeVariableInt(substr($data, $offset));
        $offset += $bytesRead;

        // 获取数据
        $streamData = substr($data, $offset, $length);

        // 获取或创建流
        $stream = $this->getStream($streamId);
        if (!$stream) {
            $type = StreamType::fromStreamId($streamId);
            $stream = new Stream($streamId, $this->_connection);
            $this->_streams[$streamId] = $stream;
        }

        // 接收数据
        $stream->receive($streamData, $streamOffset, $frame->isFinal());
    }

    /**
     * 处理 RESET_STREAM 帧
     */
    public function handleResetStream(Frame $frame): void
    {
        $data = $frame->getPayload();
        $streamId = unpack('N', substr($data, 0, 4))[1];

        $stream = $this->getStream($streamId);
        if ($stream) {
            $stream->handleResetStream();
        }
    }

    /**
     * 处理 STOP_SENDING 帧
     */
    public function handleStopSending(Frame $frame): void
    {
        $data = $frame->getPayload();
        $streamId = unpack('N', substr($data, 0, 4))[1];

        $stream = $this->getStream($streamId);
        if ($stream) {
            $stream->handleStopSending();
        }
    }

    /**
     * 处理 MAX_STREAM_DATA 帧
     */
    public function handleMaxStreamData(Frame $frame): void
    {
        $data = $frame->getPayload();
        list($streamId, $bytesRead) = $this->decodeVariableInt($data);
        list($maxData, $bytesRead) = $this->decodeVariableInt(substr($data, $bytesRead));

        $stream = $this->getStream($streamId);
        if ($stream) {
            $stream->updateMaxSendData($maxData);
        }
    }

    /**
     * 处理 STREAMS_BLOCKED 帧
     */
    public function handleStreamsBlocked(Frame $frame): void
    {
        $data = $frame->getPayload();
        list($streamLimit, $bytesRead) = $this->decodeVariableInt($data);

        // 如果我们是服务器且对方被阻塞，考虑增加流限制
        if ($this->_connection->isServer()) {
            $type = $frame->getType() === FrameType::STREAMS_BLOCKED ? 
                   StreamType::CLIENT_BIDIRECTIONAL :
                   StreamType::CLIENT_UNIDIRECTIONAL;

            $newLimit = $streamLimit * 2;
            $this->_maxStreams[$type->value] = $newLimit;

            // 发送新的限制
            $this->sendMaxStreams($newLimit, $type === StreamType::CLIENT_UNIDIRECTIONAL);
        }
    }

    /**
     * 发送 MAX_STREAMS 帧
     */
    private function sendMaxStreams(int $maxStreams, bool $isUni): void
    {
        $frameType = $isUni ? FrameType::MAX_STREAMS_UNI : FrameType::MAX_STREAMS;
        $frameData = $this->encodeVariableInt($maxStreams);
        
        $frame = new Frame($frameType, $frameData);
        $this->_connection->send($frame->encode(), $frameType);
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

    /**
     * 解码变长整数
     */
    private function decodeVariableInt(string $data): array
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
        }
        throw new \RuntimeException('未知的 prefix：' . $prefix);
    }
} 