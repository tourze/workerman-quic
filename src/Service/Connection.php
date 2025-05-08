<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\ConnectionState;
use Tourze\Workerman\QUIC\Enum\FrameType;
use Tourze\Workerman\QUIC\Enum\PacketType;
use Workerman\Connection\ConnectionInterface;

class Connection
{
    /**
     * 当前状态
     * @var ConnectionState
     */
    private $_state = ConnectionState::NEW;

    /**
     * 本地连接 ID
     * @var string
     */
    private $_localConnectionId;

    /**
     * 远程连接 ID
     * @var string
     */
    private $_remoteConnectionId;

    /**
     * 下一个发送包号
     * @var int
     */
    private $_nextPacketNumber = 0;

    /**
     * 最大接收包号
     * @var int
     */
    private $_largestReceivedPacketNumber = -1;

    /**
     * Workerman 连接实例
     * @var ConnectionInterface
     */
    private $_connection;

    /**
     * 是否为服务端
     * @var bool
     */
    private $_isServer;

    /**
     * 令牌密钥
     * @var string
     */
    private $_tokenKey;

    /**
     * 最大双向流数量
     * @var int
     */
    private $_maxBidiStreams = 100;

    /**
     * 最大单向流数量
     * @var int
     */
    private $_maxUniStreams = 100;

    /**
     * 地址验证令牌
     * @var string|null
     */
    private $_retryToken = null;

    /**
     * 路径验证状态
     * @var array
     */
    private $_pathValidation = [
        'challenge' => null,
        'response' => null,
        'timeout' => null
    ];

    /**
     * 路径状态
     * @var array
     */
    private $_paths = [
        'active' => null,
        'probing' => [],
        'validated' => []
    ];

    /**
     * 首选地址
     * @var array|null
     */
    private $_preferredAddress = null;

    /**
     * 空闲超时时间(秒)
     * @var int
     */
    private $_idleTimeout = 30;

    /**
     * 最后活动时间
     * @var int
     */
    private $_lastActivityTime;

    /**
     * 无状态重置令牌
     * @var string|null
     */
    private $_statelessResetToken = null;

    /**
     * 关闭状态
     * @var array
     */
    private $_closeState = [
        'error_code' => 0,
        'frame_type' => null,
        'reason' => '',
        'drain_timeout' => null
    ];

    /**
     * 包管理器
     * @var PacketManager
     */
    private $_packetManager;

    /**
     * 流数据回调
     * @var callable[]
     */
    private $_streamCallbacks = [];

    /**
     * 构造函数
     * @param ConnectionInterface $connection
     * @param bool $isServer
     */
    public function __construct(ConnectionInterface $connection, bool $isServer = false)
    {
        $this->_connection = $connection;
        $this->_isServer = $isServer;
        $this->_localConnectionId = $this->generateConnectionId();
        $this->_packetManager = new PacketManager();
    }

    /**
     * 处理收到的包
     * @param Packet $packet
     */
    public function handlePacket(Packet $packet): void
    {
        // 更新远程连接 ID
        if ($this->_remoteConnectionId === null) {
            $this->_remoteConnectionId = $packet->getSourceConnectionId();
        }

        // 检查 ECN 标记
        $ecnSet = ($packet->getFlags() & 0x03) === 0x03;

        // 处理包
        $this->_packetManager->processReceivedPacket($packet, $ecnSet);

        // 根据包类型处理
        $packetType = PacketType::from($packet->getFlags() & 0x30);
        switch ($packetType) {
            case PacketType::INITIAL:
                $this->handleInitialPacket($packet);
                break;
            case PacketType::HANDSHAKE:
                $this->handleHandshakePacket($packet);
                break;
            case PacketType::ZERO_RTT:
                $this->handleZeroRTTPacket($packet);
                break;
            default:
                $this->handleOneRTTPacket($packet);
                break;
        }

        // 生成并发送 ACK
        $ackFrame = $this->_packetManager->generateAckFrame();
        if ($ackFrame !== null) {
            $frame = new Frame(FrameType::ACK, $ackFrame);
            $this->send($frame->encode(), FrameType::ACK);
        }
    }

    /**
     * 发送数据
     * @param string $data
     * @param PacketType|FrameType $type
     */
    public function send(string $data, PacketType|FrameType $type): void
    {
        if ($type instanceof FrameType && !$this->_state->canSendData()) {
            return;
        }

        if ($type instanceof FrameType) {
            // 如果是帧类型，创建一个 1-RTT 包
            $packet = new Packet(
                0x30, // 1-RTT 包类型
                QUICProtocol::VERSION,
                $this->_remoteConnectionId,
                $this->_localConnectionId,
                $this->_nextPacketNumber++,
                $data
            );
        } else {
            // 如果是包类型
            $packet = new Packet(
                $type->value,
                QUICProtocol::VERSION,
                $this->_remoteConnectionId,
                $this->_localConnectionId,
                $this->_nextPacketNumber++,
                $data
            );
        }

        $this->_connection->send($packet->encode());
    }

    /**
     * 处理初始包
     * @param Packet $packet
     */
    private function handleInitialPacket(Packet $packet): void
    {
        if ($this->_state === ConnectionState::NEW) {
            $this->_state = ConnectionState::HANDSHAKING;
            // TODO: 实现 TLS 握手
        }
    }

    /**
     * 处理握手包
     * @param Packet $packet
     */
    private function handleHandshakePacket(Packet $packet): void
    {
        if ($this->_state->isHandshaking()) {
            // TODO: 继续 TLS 握手
        }
    }

    /**
     * 处理 0-RTT 包
     * @param Packet $packet
     */
    private function handleZeroRTTPacket(Packet $packet): void
    {
        // TODO: 实现 0-RTT 数据处理
    }

    /**
     * 处理 1-RTT 包
     * @param Packet $packet
     */
    private function handleOneRTTPacket(Packet $packet): void
    {
        if ($this->_state->canReceiveData()) {
            // 处理应用数据
            $frames = $this->parseFrames($packet->getPayload());
            foreach ($frames as $frame) {
                $this->handleFrame($frame);
            }
        }
    }

    /**
     * 处理帧
     * @param Frame $frame
     */
    private function handleFrame(Frame $frame): void
    {
        // 更新活动时间
        $this->updateLastActivityTime();

        switch ($frame->getType()) {
            case FrameType::STREAM:
                // TODO: 处理流数据
                break;
            case FrameType::ACK:
                $this->_packetManager->handleAckFrame($frame->getPayload());
                break;
            case FrameType::PING:
                // 发送 PONG
                $this->send('', FrameType::PONG);
                break;
            case FrameType::NEW_TOKEN:
                $this->handleNewToken($frame->getPayload());
                break;
            case FrameType::MAX_STREAMS:
            case FrameType::MAX_STREAMS_UNI:
                $this->handleMaxStreams($frame->getPayload(), $frame->getType());
                break;
            case FrameType::STREAMS_BLOCKED:
            case FrameType::STREAMS_BLOCKED_UNI:
                $this->handleStreamsBlocked($frame->getPayload(), $frame->getType());
                break;
            case FrameType::PATH_CHALLENGE:
                $this->handlePathChallenge($frame->getPayload());
                break;
            case FrameType::PATH_RESPONSE:
                $this->handlePathResponse($frame->getPayload());
                break;
            case FrameType::NEW_CONNECTION_ID:
                $this->handleNewConnectionId($frame->getPayload());
                break;
            case FrameType::PREFERRED_ADDRESS:
                $this->handlePreferredAddress($frame->getPayload());
                break;
            case FrameType::CONNECTION_CLOSE:
                $this->handleConnectionClose($frame);
                break;
            // ... 处理其他帧类型
        }
    }

    /**
     * 解析帧
     * @param string $data
     * @return Frame[]
     */
    private function parseFrames(string $data): array
    {
        $frames = [];
        $offset = 0;
        $length = strlen($data);

        while ($offset < $length) {
            $frame = Frame::decode(substr($data, $offset));
            $frames[] = $frame;
            $offset += strlen($frame->encode());
        }

        return $frames;
    }

    /**
     * 生成连接 ID
     * @return string
     */
    public function generateConnectionId(): string
    {
        return random_bytes(8); // 使用 8 字节的随机数作为连接 ID
    }

    /**
     * 获取连接状态
     * @return ConnectionState
     */
    public function getState(): ConnectionState
    {
        return $this->_state;
    }

    /**
     * 获取本地连接 ID
     * @return string
     */
    public function getLocalConnectionId(): string
    {
        return $this->_localConnectionId;
    }

    /**
     * 获取远程连接 ID
     * @return string|null
     */
    public function getRemoteConnectionId(): ?string
    {
        return $this->_remoteConnectionId;
    }

    /**
     * 判断是否为服务端
     * @return bool
     */
    public function isServer(): bool
    {
        return $this->_isServer;
    }

    /**
     * 生成地址验证令牌
     * @param string $clientAddress
     * @return string
     */
    private function generateToken(string $clientAddress): string
    {
        // 令牌格式: HMAC(token_key, client_address || current_timestamp)
        $data = $clientAddress . pack('J', time());
        return hash_hmac('sha256', $data, $this->_tokenKey, true);
    }

    /**
     * 验证令牌
     * @param string $token
     * @param string $clientAddress
     * @return bool
     */
    private function validateToken(string $token, string $clientAddress): bool
    {
        // 提取时间戳
        $timestamp = unpack('J', substr($token, -8))[1];
        
        // 检查令牌是否过期 (10分钟)
        if (time() - $timestamp > 600) {
            return false;
        }

        // 验证 HMAC
        $expectedToken = $this->generateToken($clientAddress);
        return hash_equals($token, $expectedToken);
    }

    /**
     * 发送重试包
     * @param string $clientAddress
     */
    private function sendRetryPacket(string $clientAddress): void
    {
        // 生成新令牌
        $this->_retryToken = $this->generateToken($clientAddress);
        
        // 创建重试包
        $packet = new Packet(
            PacketType::RETRY->value,
            QUICProtocol::VERSION,
            $this->_remoteConnectionId,
            $this->_localConnectionId,
            0,
            $this->_retryToken
        );
        
        $this->_connection->send($packet->encode());
    }

    /**
     * 发起路径验证
     * @param string $newPath
     */
    public function initiatePathValidation(string $newPath): void
    {
        // 生成随机挑战数据
        $this->_pathValidation['challenge'] = random_bytes(8);
        
        // 设置超时
        $this->_pathValidation['timeout'] = time() + 5;
        
        // 发送 PATH_CHALLENGE 帧
        $frame = new Frame(
            FrameType::PATH_CHALLENGE,
            $this->_pathValidation['challenge']
        );
        
        $this->send($frame->encode(), FrameType::PATH_CHALLENGE);
    }

    /**
     * 处理路径验证响应
     * @param string $data
     * @return bool
     */
    private function handlePathResponse(string $data): bool
    {
        // 检查响应是否匹配挑战
        if ($data !== $this->_pathValidation['challenge']) {
            return false;
        }
        
        // 检查是否超时
        if (time() > $this->_pathValidation['timeout']) {
            return false;
        }
        
        // 验证成功,将探测路径移至已验证列表
        foreach ($this->_paths['probing'] as $i => $path) {
            if ($path['state'] === 'probing') {
                $path['state'] = 'validated';
                unset($this->_paths['probing'][$i]);
                $this->_paths['validated'][] = $path;
                
                // 如果是首选地址的路径,自动切换
                if ($this->isPreferredAddressPath($path)) {
                    $this->switchToPath($path);
                }
                break;
            }
        }
        
        // 重置验证状态
        $this->_pathValidation = [
            'challenge' => null,
            'response' => null,
            'timeout' => null
        ];
        
        return true;
    }

    /**
     * 处理路径挑战
     * @param string $data
     */
    private function handlePathChallenge(string $data): void
    {
        // 发送 PATH_RESPONSE 帧
        $frame = new Frame(FrameType::PATH_RESPONSE, $data);
        $this->send($frame->encode(), FrameType::PATH_RESPONSE);
    }

    /**
     * 探测新路径
     * @param string $localAddress
     * @param string $remoteAddress
     */
    public function probePath(string $localAddress, string $remoteAddress): void
    {
        $path = [
            'local' => $localAddress,
            'remote' => $remoteAddress,
            'state' => 'probing',
            'rtt' => null,
            'congestion_window' => null
        ];
        
        $this->_paths['probing'][] = $path;
        
        // 发起路径验证
        $this->initiatePathValidation($remoteAddress);
    }

    /**
     * 发起连接迁移
     * @param string $newLocalAddress
     * @param string $newRemoteAddress
     */
    public function initiateMigration(string $newLocalAddress, string $newRemoteAddress): void
    {
        // 检查是否已验证过该路径
        foreach ($this->_paths['validated'] as $path) {
            if ($path['local'] === $newLocalAddress && $path['remote'] === $newRemoteAddress) {
                $this->switchToPath($path);
                return;
            }
        }
        
        // 如果是新路径,先进行探测
        $this->probePath($newLocalAddress, $newRemoteAddress);
    }

    /**
     * 切换到新路径
     * @param array $path
     */
    private function switchToPath(array $path): void
    {
        // 保存旧路径
        if ($this->_paths['active']) {
            $this->_paths['validated'][] = $this->_paths['active'];
        }
        
        // 激活新路径
        $this->_paths['active'] = $path;
        
        // 重置拥塞控制
        $this->resetCongestionControl();
        
        // 通知对端
        $this->sendNewConnectionId();
    }

    /**
     * 设置服务器首选地址
     * @param string $address
     * @param int $port
     */
    public function setPreferredAddress(string $address, int $port): void
    {
        if ($this->_isServer) {
            $this->_preferredAddress = [
                'address' => $address,
                'port' => $port
            ];
            
            // 通知客户端
            $this->sendPreferredAddress();
        }
    }

    /**
     * 发送首选地址
     */
    private function sendPreferredAddress(): void
    {
        if (!$this->_preferredAddress) {
            return;
        }
        
        // 创建首选地址帧
        $frameData = pack('a*nP', 
            $this->_preferredAddress['address'],
            $this->_preferredAddress['port'],
            $this->generateConnectionId()
        );
        
        $frame = new Frame(FrameType::PREFERRED_ADDRESS, $frameData);
        $this->send($frame->encode(), FrameType::PREFERRED_ADDRESS);
    }

    /**
     * 判断是否为首选地址路径
     * @param array $path
     * @return bool
     */
    private function isPreferredAddressPath(array $path): bool
    {
        if (!$this->_preferredAddress) {
            return false;
        }
        
        return $path['remote'] === $this->_preferredAddress['address'] && 
               $path['port'] === $this->_preferredAddress['port'];
    }

    /**
     * 重置拥塞控制
     */
    public function resetCongestionControl(): void
    {
        // TODO: 实现拥塞控制重置
    }

    /**
     * 发送新连接 ID
     */
    public function sendNewConnectionId(): void
    {
        $newId = $this->generateConnectionId();
        
        $frame = new Frame(
            FrameType::NEW_CONNECTION_ID,
            pack('Ca*', strlen($newId), $newId)
        );
        
        $this->send($frame->encode(), FrameType::NEW_CONNECTION_ID);
    }

    /**
     * 处理新连接 ID
     * @param string $data
     */
    private function handleNewConnectionId(string $data): void
    {
        $length = ord($data[0]);
        $newId = substr($data, 1, $length);
        
        // 更新远程连接 ID
        $this->_remoteConnectionId = $newId;
    }

    /**
     * 处理首选地址
     * @param string $data
     */
    private function handlePreferredAddress(string $data): void
    {
        if ($this->_isServer) {
            return;
        }
        
        // 解析首选地址
        $address = unpack('a*', $data)[1];
        $port = unpack('n', substr($data, strlen($address)))[1];
        $connectionId = substr($data, -8);
        
        $this->_preferredAddress = [
            'address' => $address,
            'port' => $port,
            'connection_id' => $connectionId
        ];
        
        // 探测首选地址路径
        $this->probePath(
            $this->_connection->getLocalAddress(),
            $address . ':' . $port
        );
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
            $this->close(0x00, 'idle timeout');
            return true;
        }

        return false;
    }

    /**
     * 更新活动时间
     */
    private function updateLastActivityTime(): void
    {
        $this->_lastActivityTime = time();
    }

    /**
     * 发送 PING 帧
     */
    public function sendPing(): void
    {
        $this->send('', FrameType::PING);
        $this->updateLastActivityTime();
    }

    /**
     * 延长空闲超时
     * @param int $timeout 新的超时时间(秒)
     */
    public function extendIdleTimeout(int $timeout): void
    {
        $this->_idleTimeout = $timeout;
        $this->updateLastActivityTime();
    }

    /**
     * 立即关闭连接
     * @param int $errorCode 错误码
     * @param string $reason 原因
     * @param int|null $frameType 触发关闭的帧类型
     */
    public function close(int $errorCode = 0, string $reason = '', ?int $frameType = null): void
    {
        if ($this->_state === ConnectionState::CLOSED) {
            return;
        }

        // 保存关闭状态
        $this->_closeState = [
            'error_code' => $errorCode,
            'frame_type' => $frameType,
            'reason' => $reason,
            'drain_timeout' => time() + 3 * $this->_idleTimeout
        ];

        // 发送 CONNECTION_CLOSE 帧
        $frameData = pack('N', $errorCode); // 错误码
        if ($frameType !== null) {
            $frameData .= pack('N', $frameType); // 帧类型
        }
        $frameData .= pack('n', strlen($reason)) . $reason; // 原因短语

        $frame = new Frame(FrameType::CONNECTION_CLOSE, $frameData);
        $this->send($frame->encode(), FrameType::CONNECTION_CLOSE);

        // 更新状态
        $this->_state = ConnectionState::CLOSING;

        // 启动排空计时器
        $this->startDraining();
    }

    /**
     * 开始排空状态
     */
    private function startDraining(): void
    {
        // 在排空状态下:
        // 1. 不再发送新的应用数据
        // 2. 继续处理和响应 CONNECTION_CLOSE 帧
        // 3. 可以发送 CONNECTION_CLOSE 帧响应对端的关闭
        // 4. 在3倍空闲超时后完全关闭连接
    }

    /**
     * 生成无状态重置令牌
     */
    private function generateStatelessResetToken(): string
    {
        // 使用连接 ID 和静态密钥生成令牌
        $data = $this->_localConnectionId . pack('J', time());
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

        // 构造无状态重置包
        // 随机填充 + 重置令牌
        $packet = random_bytes(16) . $this->_statelessResetToken;
        
        $this->_connection->send($packet);
        $this->_state = ConnectionState::CLOSED;
    }

    /**
     * 验证无状态重置令牌
     * @param string $token
     * @return bool
     */
    public function validateStatelessResetToken(string $token): bool
    {
        if (!$this->_statelessResetToken) {
            return false;
        }

        return hash_equals($token, $this->_statelessResetToken);
    }

    /**
     * 处理 CONNECTION_CLOSE 帧
     * @param Frame $frame
     */
    private function handleConnectionClose(Frame $frame): void
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

        // 保存关闭状态
        $this->_closeState = [
            'error_code' => $errorCode,
            'frame_type' => $frameType,
            'reason' => $reason,
            'drain_timeout' => time() + 3 * $this->_idleTimeout
        ];

        // 进入排空状态
        $this->_state = ConnectionState::CLOSING;
        $this->startDraining();

        // 响应对端的关闭
        $this->close($errorCode, $reason, $frameType);
    }

    /**
     * 处理 NEW_TOKEN 帧
     * @param string $data
     */
    private function handleNewToken(string $data): void
    {
        if ($this->_isServer) {
            return; // 服务器不处理 NEW_TOKEN 帧
        }

        $tokenLength = unpack('n', substr($data, 0, 2))[1];
        $token = substr($data, 2, $tokenLength);
        
        // 保存令牌供下次连接使用
        $this->_retryToken = $token;
    }

    /**
     * 处理 MAX_STREAMS 帧
     * @param string $data
     * @param FrameType $type
     */
    private function handleMaxStreams(string $data, FrameType $type): void
    {
        $maxStreams = unpack('J', $data)[1];
        
        // 根据帧类型更新双向或单向流的限制
        if ($type === FrameType::MAX_STREAMS) {
            $this->_maxBidiStreams = $maxStreams;
        } else {
            $this->_maxUniStreams = $maxStreams;
        }
    }

    /**
     * 处理 STREAMS_BLOCKED 帧
     * @param string $data
     * @param FrameType $type
     */
    private function handleStreamsBlocked(string $data, FrameType $type): void
    {
        $streamLimit = unpack('J', $data)[1];
        
        // 如果我们是服务器且对方被阻塞，考虑增加流限制
        if ($this->_isServer) {
            $newLimit = $streamLimit * 2; // 简单的增长策略
            
            // 发送新的限制
            if ($type === FrameType::STREAMS_BLOCKED) {
                $this->sendMaxStreams($newLimit, false);
            } else {
                $this->sendMaxStreams($newLimit, true);
            }
        }
    }

    /**
     * 发送 MAX_STREAMS 帧
     * @param int $maxStreams
     * @param bool $isUni
     */
    private function sendMaxStreams(int $maxStreams, bool $isUni): void
    {
        $frameType = $isUni ? FrameType::MAX_STREAMS_UNI : FrameType::MAX_STREAMS;
        $frameData = pack('J', $maxStreams);
        
        $frame = new Frame($frameType, $frameData);
        $this->send($frame->encode(), $frameType);
    }

    /**
     * 处理流数据
     */
    public function onStreamData(int $streamId, string $data): void
    {
        if (isset($this->_streamCallbacks[$streamId])) {
            ($this->_streamCallbacks[$streamId])($data);
        }
    }

    /**
     * 处理流结束
     */
    public function onStreamEnd(int $streamId): void
    {
        if (isset($this->_streamCallbacks[$streamId])) {
            unset($this->_streamCallbacks[$streamId]);
        }
    }
}
