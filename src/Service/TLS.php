<?php

namespace Tourze\Workerman\QUIC\Service;

use OpenSSLAsymmetricKey;
use Tourze\Workerman\QUIC\Enum\TLSState;
use Tourze\Workerman\QUIC\TLS\CryptoManager;
use Tourze\Workerman\QUIC\TLS\HandshakeManager;
use Tourze\Workerman\QUIC\TLS\MessageHandler;

class TLS
{
    /**
     * TLS 状态
     */
    const STATE_INITIAL = 0;
    const STATE_HANDSHAKING = 1;
    const STATE_ESTABLISHED = 2;
    const STATE_CLOSING = 3;
    const STATE_CLOSED = 4;

    /**
     * 当前状态
     * @var int
     */
    private $_state = 0; // TLSState::INITIAL->value

    /**
     * TLS 上下文
     * @var resource|null
     */
    private $_context = null;

    /**
     * 握手管理器
     * @var HandshakeManager
     */
    private $_handshakeManager;

    /**
     * 加密管理器
     * @var CryptoManager
     */
    private $_cryptoManager;

    /**
     * 消息处理器
     * @var MessageHandler
     */
    private $_messageHandler;

    /**
     * 加密套件
     * @var int
     */
    private $_cipherSuite = QUICProtocol::TLS_AES_128_GCM_SHA256;

    /**
     * 密钥
     * @var array
     */
    private $_keys = [
        'client_handshake' => null,
        'server_handshake' => null,
        'client_application' => null,
        'server_application' => null
    ];

    /**
     * 私钥
     * @var OpenSSLAsymmetricKey|null
     */
    private $_privateKey = null;

    /**
     * 证书
     * @var string|null
     */
    private $_certificate = null;

    /**
     * 转录哈希缓冲区
     * @var array
     */
    private $_transcriptBuffer = [];

    /**
     * 构造函数
     * @param array $options
     */
    public function __construct(array $options = [])
    {
        $this->_handshakeManager = new HandshakeManager(
            $options['local_private_key'] ?? null,
            $options['local_certificate'] ?? null
        );
        $this->_cryptoManager = new CryptoManager();
        $this->_messageHandler = new MessageHandler($this->_handshakeManager, $options['local_certificate'] ?? null);
        
        $this->initContext($options);
    }

    /**
     * 初始化 TLS 上下文
     * @param array $options
     */
    private function initContext(array $options): void
    {
        $defaultOptions = [
            'verify_peer' => true,
            'verify_peer_name' => true,
            'allow_self_signed' => false,
            'ciphers' => 'TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256',
            'verify_depth' => 7,
            'disable_compression' => true,
            'single_ecdh_use' => true,
            'honor_cipher_order' => true
        ];

        $contextOptions = array_merge($defaultOptions, $options);
        
        $this->_context = stream_context_create([
            'ssl' => $contextOptions
        ]);
    }

    /**
     * 开始握手
     * @param bool $isServer
     * @return string
     */
    public function startHandshake(bool $isServer): string
    {
        if ($this->_state !== self::STATE_INITIAL) {
            return '';
        }

        $this->_state = self::STATE_HANDSHAKING;
        
        if ($isServer) {
            return $this->_handshakeManager->generateServerHello();
        } else {
            return $this->_handshakeManager->generateClientHello();
        }
    }

    /**
     * 处理握手消息
     * @param string $data
     * @return string
     */
    public function handleHandshake(string $data): string
    {
        if ($this->_state !== self::STATE_HANDSHAKING) {
            return '';
        }

        $response = '';
        $offset = 0;
        
        while ($offset < strlen($data)) {
            $type = ord($data[$offset]);
            $length = unpack('n', substr($data, $offset + 1, 2))[1];
            $message = substr($data, $offset + 3, $length);
            $offset += 3 + $length;

            switch ($type) {
                case 0x01: // ClientHello
                    $response .= $this->_messageHandler->handleClientHello($message);
                    break;
                case 0x02: // ServerHello
                    $response .= $this->_messageHandler->handleServerHello($message);
                    break;
                case 0x08: // EncryptedExtensions
                    $response .= $this->_messageHandler->handleEncryptedExtensions($message);
                    break;
                case 0x0b: // Certificate
                    $response .= $this->_messageHandler->handleCertificate($message);
                    break;
                case 0x0f: // CertificateVerify
                    $response .= $this->_messageHandler->handleCertificateVerify($message);
                    break;
                case 0x14: // Finished
                    $response .= $this->_messageHandler->handleFinished($message);
                    $this->setState(TLSState::ESTABLISHED);
                    break;
            }
        }

        return $response;
    }

    /**
     * 加密应用数据
     * @param string $data
     * @param int $packetNumber
     * @return string
     */
    public function encryptApplicationData(string $data, int $packetNumber): string
    {
        if ($this->_state !== self::STATE_ESTABLISHED) {
            return '';
        }

        $key = $this->_handshakeManager->getKey('client_application') ?? 
               $this->_handshakeManager->getKey('server_application');
        if (!$key) {
            return '';
        }

        return $this->_cryptoManager->encrypt($data, $packetNumber, $key);
    }

    /**
     * 解密应用数据
     * @param string $data
     * @param int $packetNumber
     * @return string
     */
    public function decryptApplicationData(string $data, int $packetNumber): string
    {
        if ($this->_state !== self::STATE_ESTABLISHED) {
            return '';
        }

        $key = $this->_handshakeManager->getKey('client_application') ?? 
               $this->_handshakeManager->getKey('server_application');
        if (!$key) {
            return '';
        }

        return $this->_cryptoManager->decrypt($data, $packetNumber, $key);
    }

    /**
     * 获取当前状态
     * @return int
     */
    public function getState(): int
    {
        return $this->_state;
    }

    /**
     * 获取选择的密码套件
     * @return int
     */
    public function getCipherSuite(): int
    {
        return $this->_handshakeManager->getCipherSuite();
    }

    /**
     * 设置密钥
     * @param string $type
     * @param string $key
     */
    public function setKey(string $type, string $key): void
    {
        $this->_handshakeManager->setKey($type, $key);
    }

    /**
     * 获取密钥
     * @param string $type
     * @return string|null
     */
    public function getKey(string $type): ?string
    {
        return $this->_handshakeManager->getKey($type);
    }

    /**
     * 更新状态
     * @param TLSState $state
     */
    private function setState(TLSState $state): void 
    {
        $this->_state = $state->value;
    }
} 