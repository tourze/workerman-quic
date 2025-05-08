<?php

namespace Tourze\Workerman\QUIC\TLS;

use Tourze\Workerman\QUIC\Service\QUICProtocol;

class HandshakeManager
{
    /**
     * 转录哈希缓冲区
     * @var array
     */
    private $_transcriptBuffer = [];

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
     * 加密套件
     * @var int
     */
    private $_cipherSuite = QUICProtocol::TLS_AES_128_GCM_SHA256;

    public function __construct(?string $privateKey = null, ?string $certificate = null)
    {
        if ($privateKey) {
            $this->_privateKey = openssl_pkey_get_private($privateKey);
        }
        if ($certificate) {
            $this->_certificate = $certificate;
        }
    }

    /**
     * 生成 Client Hello
     */
    public function generateClientHello(): string
    {
        $data = '';
        
        // 协议版本 (TLS 1.3)
        $data .= pack('n', 0x0304);
        
        // 随机数 (32 字节)
        $data .= random_bytes(32);
        
        // Session ID
        $data .= chr(32) . random_bytes(32);
        
        // 密码套件列表
        $cipherSuites = [
            QUICProtocol::TLS_AES_128_GCM_SHA256,
            QUICProtocol::TLS_AES_256_GCM_SHA384,
            QUICProtocol::TLS_CHACHA20_POLY1305_SHA256
        ];
        $data .= pack('n', count($cipherSuites) * 2);
        foreach ($cipherSuites as $suite) {
            $data .= pack('n', $suite);
        }
        
        // 压缩方法 (null)
        $data .= chr(1) . chr(0);
        
        // 扩展
        $extensions = $this->generateClientExtensions();
        $data .= pack('n', strlen($extensions)) . $extensions;

        return $this->wrapHandshakeMessage(0x01, $data);
    }

    /**
     * 生成 Server Hello
     */
    public function generateServerHello(): string
    {
        $data = '';
        
        // 协议版本 (TLS 1.3)
        $data .= pack('n', 0x0304);
        
        // 随机数 (32 字节)
        $data .= random_bytes(32);
        
        // Session ID
        $data .= chr(32) . random_bytes(32);
        
        // 选择的密码套件
        $data .= pack('n', $this->_cipherSuite);
        
        // 压缩方法 (null)
        $data .= chr(0);
        
        // 扩展
        $extensions = $this->generateServerExtensions();
        $data .= pack('n', strlen($extensions)) . $extensions;
        
        return $this->wrapHandshakeMessage(0x02, $data);
    }

    /**
     * 生成证书验证
     */
    public function generateCertificateVerify(): string
    {
        if (!$this->_privateKey) {
            return '';
        }
        
        $data = str_repeat(chr(0x20), 64);
        $data .= "TLS 1.3, server CertificateVerify";
        $data .= chr(0);
        
        $data .= $this->computeTranscriptHash(0x0b);
        
        openssl_sign($data, $signature, $this->_privateKey, OPENSSL_ALGO_SHA256);
        
        $verifyData = pack('n', 0x0403); // ecdsa_secp256r1_sha256
        $verifyData .= pack('n', strlen($signature)) . $signature;
        
        return $this->wrapHandshakeMessage(0x0f, $verifyData);
    }

    /**
     * 生成完成消息
     */
    public function generateFinished(): string
    {
        return $this->wrapHandshakeMessage(0x14, $this->computeVerifyData());
    }

    /**
     * 计算转录哈希
     * @param int $upToType
     * @return string
     */
    public function computeTranscriptHash(int $upToType): string
    {
        $context = hash_init('sha256');
        
        foreach ($this->_transcriptBuffer as $message) {
            if ($message['type'] > $upToType) {
                break;
            }
            
            $data = chr($message['type']) . 
                    pack('N', strlen($message['data']))[1] . 
                    pack('n', strlen($message['data'])) . 
                    $message['data'];
            
            hash_update($context, $data);
        }
        
        return hash_final($context, true);
    }

    /**
     * 计算验证数据
     * @return string
     */
    public function computeVerifyData(): string
    {
        $key = $this->_keys['client_handshake'] ?? $this->_keys['server_handshake'];
        if (!$key) {
            throw new \Exception('Handshake key not available');
        }
        
        $transcriptHash = $this->computeTranscriptHash(0x0f);
        $finishedKey = hash_hmac('sha256', 'tls13 finished', $key, true);
        
        return hash_hmac('sha256', $transcriptHash, $finishedKey, true);
    }

    /**
     * 包装握手消息
     */
    private function wrapHandshakeMessage(int $type, string $data): string
    {
        $this->_transcriptBuffer[] = [
            'type' => $type,
            'data' => $data
        ];
        
        return chr($type) . pack('N', strlen($data))[1] . pack('n', strlen($data)) . $data;
    }

    /**
     * 生成客户端扩展
     */
    private function generateClientExtensions(): string
    {
        $extensions = '';

        // supported_versions
        $versions = pack('n*', 0x0304); // TLS 1.3
        $extensions .= pack('n', 0x002b) . pack('n', strlen($versions) + 1) . chr(strlen($versions)) . $versions;

        // supported_groups
        $groups = pack('n*', 0x0017, 0x0018); // secp256r1, secp384r1
        $extensions .= pack('n', 0x000a) . pack('n', strlen($groups) + 2) . pack('n', strlen($groups)) . $groups;

        // signature_algorithms
        $sigAlgs = pack('n*', 0x0403, 0x0503, 0x0804);
        $extensions .= pack('n', 0x000d) . pack('n', strlen($sigAlgs) + 2) . pack('n', strlen($sigAlgs)) . $sigAlgs;

        // key_share
        $keyShare = $this->generateKeyShare();
        $extensions .= pack('n', 0x0033) . pack('n', strlen($keyShare)) . $keyShare;

        // quic_transport_parameters
        $quicParams = $this->generateQuicTransportParameters();
        $extensions .= pack('n', 0xffa5) . pack('n', strlen($quicParams)) . $quicParams;

        return $extensions;
    }

    /**
     * 生成服务端扩展
     */
    private function generateServerExtensions(): string
    {
        $extensions = '';

        // supported_versions
        $extensions .= pack('n', 0x002b) . pack('n', 2) . pack('n', 0x0304);

        // key_share
        $keyShare = $this->generateKeyShare();
        $extensions .= pack('n', 0x0033) . pack('n', strlen($keyShare)) . $keyShare;

        // quic_transport_parameters
        $quicParams = $this->generateQuicTransportParameters();
        $extensions .= pack('n', 0xffa5) . pack('n', strlen($quicParams)) . $quicParams;

        return $extensions;
    }

    /**
     * 生成密钥共享
     */
    private function generateKeyShare(): string
    {
        $keyPair = openssl_pkey_new([
            'curve_name' => 'prime256v1',
            'private_key_type' => OPENSSL_KEYTYPE_EC
        ]);
        
        $details = openssl_pkey_get_details($keyPair);
        $publicKey = $details['key'];
        
        return pack('n', 0x0017) . pack('n', strlen($publicKey)) . $publicKey;
    }

    /**
     * 生成 QUIC 传输参数
     */
    private function generateQuicTransportParameters(): string
    {
        $params = '';
        
        // initial_max_stream_data_bidi_local
        $params .= pack('n', 0x0005) . pack('n', 4) . pack('N', 256 * 1024);
        
        // initial_max_data
        $params .= pack('n', 0x0004) . pack('n', 4) . pack('N', 1024 * 1024);
        
        // initial_max_streams_bidi
        $params .= pack('n', 0x0008) . pack('n', 2) . pack('n', 100);
        
        // idle_timeout
        $params .= pack('n', 0x0001) . pack('n', 2) . pack('n', 30);
        
        return $params;
    }

    public function getCipherSuite(): int
    {
        return $this->_cipherSuite;
    }

    public function setCipherSuite(int $suite): void
    {
        $this->_cipherSuite = $suite;
    }

    public function setKey(string $type, string $key): void
    {
        if (isset($this->_keys[$type])) {
            $this->_keys[$type] = $key;
        }
    }

    public function getKey(string $type): ?string
    {
        return $this->_keys[$type] ?? null;
    }

    /**
     * 生成加密扩展
     * @return string
     */
    public function generateEncryptedExtensions(): string
    {
        $extensions = '';
        
        // quic_transport_parameters
        $quicParams = $this->generateQuicTransportParameters();
        $extensions .= pack('n', 0xffa5) . pack('n', strlen($quicParams)) . $quicParams;
        
        return $this->wrapHandshakeMessage(0x08, pack('n', strlen($extensions)) . $extensions);
    }

    /**
     * 生成证书
     * @return string
     */
    public function generateCertificate(): string
    {
        if (!$this->_certificate) {
            return '';
        }
        
        $certData = '';
        $certData .= chr(0); // 证书请求上下文长度为 0
        
        $certList = '';
        $certList .= pack('N', strlen($this->_certificate))[1] . pack('n', strlen($this->_certificate)) . $this->_certificate;
        $certList .= pack('n', 0); // 没有扩展
        
        $certData .= pack('N', strlen($certList))[1] . pack('n', strlen($certList)) . $certList;
        
        return $this->wrapHandshakeMessage(0x0b, $certData);
    }
} 