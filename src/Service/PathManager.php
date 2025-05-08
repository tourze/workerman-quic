<?php

namespace Tourze\Workerman\QUIC\Service;

use Tourze\Workerman\QUIC\Enum\FrameType;
use Tourze\Workerman\QUIC\Enum\PathState;

class PathManager
{
    /**
     * 路径验证状态
     */
    private array $_validation = [
        'challenge' => null,
        'response' => null,
        'timeout' => null
    ];

    /**
     * 路径状态
     */
    private array $_paths = [
        'active' => null,
        'probing' => [],
        'validated' => []
    ];

    /**
     * 首选地址
     */
    private ?array $_preferredAddress = null;

    /**
     * QUIC 连接实例
     */
    private Connection $_connection;

    public function __construct(Connection $connection)
    {
        $this->_connection = $connection;
    }

    /**
     * 发起路径验证
     */
    public function initiateValidation(string $newPath): void
    {
        $this->_validation['challenge'] = random_bytes(8);
        $this->_validation['timeout'] = time() + 5;
        
        $frame = new Frame(FrameType::PATH_CHALLENGE, $this->_validation['challenge']);
        $this->_connection->send($frame->encode(), FrameType::PATH_CHALLENGE);
    }

    /**
     * 处理路径验证响应
     */
    public function handleResponse(string $data): bool
    {
        if ($data !== $this->_validation['challenge']) {
            return false;
        }
        
        if (time() > $this->_validation['timeout']) {
            return false;
        }
        
        foreach ($this->_paths['probing'] as $i => $path) {
            if ($path['state'] === PathState::PROBING->value) {
                $path['state'] = PathState::VALIDATED->value;
                unset($this->_paths['probing'][$i]);
                $this->_paths['validated'][] = $path;
                
                if ($this->isPreferredAddressPath($path)) {
                    $this->switchToPath($path);
                }
                break;
            }
        }
        
        $this->_validation = [
            'challenge' => null,
            'response' => null,
            'timeout' => null
        ];

        return true;
    }

    /**
     * 处理路径挑战
     */
    public function handleChallenge(string $data): void
    {
        $frame = new Frame(FrameType::PATH_RESPONSE, $data);
        $this->_connection->send($frame->encode(), FrameType::PATH_RESPONSE);
    }

    /**
     * 探测新路径
     */
    public function probePath(string $localAddress, string $remoteAddress): void
    {
        $path = [
            'local' => $localAddress,
            'remote' => $remoteAddress,
            'state' => PathState::PROBING->value,
            'rtt' => null,
            'congestion_window' => null
        ];

        $this->_paths['probing'][] = $path;
        $this->initiateValidation($remoteAddress);
    }

    /**
     * 切换到新路径
     */
    private function switchToPath(array $path): void
    {
        if ($this->_paths['active']) {
            $this->_paths['validated'][] = $this->_paths['active'];
        }
        
        $this->_paths['active'] = $path;
        $this->_connection->resetCongestionControl();
        $this->_connection->sendNewConnectionId();
    }

    /**
     * 设置首选地址
     */
    public function setPreferredAddress(string $address, int $port): void
    {
        if ($this->_connection->isServer()) {
            $this->_preferredAddress = [
                'address' => $address,
                'port' => $port
            ];
            
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
        
        $frameData = pack('a*nP', 
            $this->_preferredAddress['address'],
            $this->_preferredAddress['port'],
            $this->_connection->generateConnectionId()
        );
        
        $frame = new Frame(FrameType::PREFERRED_ADDRESS, $frameData);
        $this->_connection->send($frame->encode(), FrameType::PREFERRED_ADDRESS);
    }

    /**
     * 判断是否为首选地址路径
     */
    private function isPreferredAddressPath(array $path): bool
    {
        if (!$this->_preferredAddress) {
            return false;
        }

        return $path['remote'] === $this->_preferredAddress['address'] && 
               $path['port'] === $this->_preferredAddress['port'];
    }
}
