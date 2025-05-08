<?php

namespace Tourze\Workerman\QUIC\TLS;

use Tourze\Workerman\QUIC\Service\QUICProtocol;

class MessageHandler
{
    /**
     * 证书
     * @var string|null
     */
    private $_certificate = null;

    /**
     * 握手管理器
     * @var HandshakeManager
     */
    private $_handshakeManager;

    public function __construct(HandshakeManager $handshakeManager, ?string $certificate = null)
    {
        $this->_handshakeManager = $handshakeManager;
        $this->_certificate = $certificate;
    }

    /**
     * 处理 Client Hello
     * @param string $message
     * @return string
     */
    public function handleClientHello(string $message): string
    {
        // 解析 Client Hello
        $offset = 2; // 跳过版本
        $random = substr($message, $offset, 32);
        $offset += 32;
        
        $sessionIdLength = ord($message[$offset]);
        $sessionId = substr($message, $offset + 1, $sessionIdLength);
        $offset += 1 + $sessionIdLength;
        
        $cipherSuitesLength = unpack('n', substr($message, $offset, 2))[1];
        $cipherSuites = substr($message, $offset + 2, $cipherSuitesLength);
        $offset += 2 + $cipherSuitesLength;
        
        // 选择密码套件
        $this->_handshakeManager->setCipherSuite(QUICProtocol::TLS_AES_128_GCM_SHA256);
        
        // 生成响应
        $response = $this->_handshakeManager->generateServerHello();
        $response .= $this->_handshakeManager->generateEncryptedExtensions();
        $response .= $this->_handshakeManager->generateCertificate();
        $response .= $this->_handshakeManager->generateCertificateVerify();
        $response .= $this->_handshakeManager->generateFinished();
        
        return $response;
    }

    /**
     * 处理 Server Hello
     * @param string $message
     * @return string
     */
    public function handleServerHello(string $message): string
    {
        // 解析 Server Hello
        $offset = 2; // 跳过版本
        $random = substr($message, $offset, 32);
        $offset += 32;
        
        $sessionIdLength = ord($message[$offset]);
        $sessionId = substr($message, $offset + 1, $sessionIdLength);
        $offset += 1 + $sessionIdLength;
        
        $cipherSuite = unpack('n', substr($message, $offset, 2))[1];
        $this->_handshakeManager->setCipherSuite($cipherSuite);
        
        // 生成响应
        return $this->_handshakeManager->generateFinished();
    }

    /**
     * 处理加密扩展
     * @param string $message
     * @return string
     */
    public function handleEncryptedExtensions(string $message): string
    {
        // 解析加密扩展
        $extensionsLength = unpack('n', substr($message, 0, 2))[1];
        $extensions = substr($message, 2, $extensionsLength);
        
        // 处理 QUIC 传输参数
        $offset = 0;
        while ($offset < $extensionsLength) {
            $type = unpack('n', substr($extensions, $offset, 2))[1];
            $length = unpack('n', substr($extensions, $offset + 2, 2))[1];
            $data = substr($extensions, $offset + 4, $length);
            
            if ($type === 0xffa5) { // QUIC 传输参数
                $this->handleQuicTransportParameters($data);
            }
            
            $offset += 4 + $length;
        }
        
        return '';
    }

    /**
     * 处理证书
     * @param string $message
     * @return string
     */
    public function handleCertificate(string $message): string
    {
        // 跳过证书请求上下文
        $contextLength = ord($message[0]);
        $offset = 1 + $contextLength;
        
        // 解析证书链
        $certsLength = unpack('N', chr(0) . substr($message, $offset, 3))[1];
        $offset += 3;
        
        while ($offset < strlen($message)) {
            $certLength = unpack('N', chr(0) . substr($message, $offset, 3))[1];
            $offset += 3;
            
            $cert = substr($message, $offset, $certLength);
            $offset += $certLength;
            
            // 验证证书
            if (!openssl_x509_verify($cert, $this->_certificate)) {
                throw new \Exception('Certificate verification failed');
            }
            
            // 跳过扩展
            $extensionsLength = unpack('n', substr($message, $offset, 2))[1];
            $offset += 2 + $extensionsLength;
        }
        
        return '';
    }

    /**
     * 处理证书验证
     * @param string $message
     * @return string
     */
    public function handleCertificateVerify(string $message): string
    {
        // 解析签名算法
        $algorithm = unpack('n', substr($message, 0, 2))[1];
        
        // 解析签名
        $signatureLength = unpack('n', substr($message, 2, 2))[1];
        $signature = substr($message, 4, $signatureLength);
        
        // 验证签名
        $data = str_repeat(chr(0x20), 64);
        $data .= "TLS 1.3, server CertificateVerify";
        $data .= chr(0);
        
        // 添加转录哈希
        $data .= $this->_handshakeManager->computeTranscriptHash(0x0b);
        
        if (!openssl_verify($data, $signature, $this->_certificate, OPENSSL_ALGO_SHA256)) {
            throw new \Exception('Signature verification failed');
        }
        
        return '';
    }

    /**
     * 处理完成消息
     * @param string $message
     * @return string
     */
    public function handleFinished(string $message): string
    {
        // 验证完成消息
        $expectedVerifyData = $this->_handshakeManager->computeVerifyData();
        if ($message !== $expectedVerifyData) {
            throw new \Exception('Finished message verification failed');
        }
        
        return '';
    }

    /**
     * 处理 QUIC 传输参数
     * @param string $data
     */
    private function handleQuicTransportParameters(string $data): void
    {
        $offset = 0;
        while ($offset < strlen($data)) {
            $id = unpack('n', substr($data, $offset, 2))[1];
            $length = unpack('n', substr($data, $offset + 2, 2))[1];
            $value = substr($data, $offset + 4, $length);
            
            switch ($id) {
                case 0x0005: // initial_max_stream_data_bidi_local
                    // 处理双向流的初始最大数据量
                    break;
                case 0x0004: // initial_max_data
                    // 处理连接的初始最大数据量
                    break;
                case 0x0008: // initial_max_streams_bidi
                    // 处理双向流的初始最大数量
                    break;
                case 0x0001: // idle_timeout
                    // 处理空闲超时
                    break;
            }
            
            $offset += 4 + $length;
        }
    }
}
